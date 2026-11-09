// RECORD.md section 5.4's deposits, on every leg: the writer's deposit path, for a sidecar whose author's vault takes
// its entries by deposit rather than from a stream of its own (the author's other untagged sidecars and its sponsored
// tagged ones, §8.5, §16.8), and the batch format an ingester reads back (record_ingest.go).
//
// A deposit file holds one RecordDepositBatch of at most 64 entries and DepositByteCount bytes, an entry past the bytes
// alone in a batch of its own; each RecordDeposit is {entry, key, salt}, the entry's RecordEntry with its key_slot_id
// empty and key_index 0, and the body's key and salt the ingester re-slots. The binding seals the batch under the
// deposit's one object key, which a slot holds HPKE-wrapped to the repo's drop key (§11.12), so the per-entry keys ride
// inside the sealed deposit, and an ERASE of an unconsumed deposit's slot opens neither the batch nor its entries.
//
// A deposit goes as the writer's push loop sends every plan (record_batch.go): journaled first, the same push id and
// deposit id on a retry, a new pair after a refusal that spends them, such as a deposit re-wrapped to a newer drop key
// after 412 GATE_CLOSED, and its entries' signed bytes never re-signed. A depositor keeps what it deposited until an
// ingester consumes it (D-MCP-10), which is RECORD-M3-10's: until that lands, a committed deposit is acknowledged in
// the journal and kept nowhere else.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A deposit batch's entry bound (RecordDepositBatch's comment), a format value.
const recordDepositEntryCount = 64

// A deposit batch that breaks section 5.4's shape: not a RecordDepositBatch, past 64 entries, past its byte bound with
// more than one entry, or an entry whose key, salt or slot fields are not a deposit's. An ingester consumes it
// unrecorded, with an alarm.
var ErrRecordDepositInvalid = errors.New("record deposit invalid")

// What one deposit of entry adds to a batch's bytes.
func recordDepositByteCount(deposit *protocol.RecordDeposit) int {
	return protowire.SizeTag(1) + protowire.SizeBytes(proto.Size(deposit))
}

// The waiting entries the next deposit takes, from the lowest seq: at most 64, and within byteCount unless the first
// alone passes it, which then goes alone.
func recordDepositTake(queue *recordLogQueue, seqs []uint64, byteCount int) []*RecordSealedEntry {
	taken := []*RecordSealedEntry{}
	takenByteCount := 0
	for _, seq := range seqs {
		if recordDepositEntryCount <= len(taken) {
			break
		}
		entry := queue.waitingSeqEntries[seq]
		// sized by reference, so no copy of the key is left behind
		entryByteCount := recordDepositByteCount(&protocol.RecordDeposit{Entry: entry.EntryBytes(nil, 0), Key: entry.Key, Salt: entry.Salt})
		if 0 < len(taken) && byteCount < takenByteCount+entryByteCount {
			break
		}
		taken = append(taken, entry)
		takenByteCount += entryByteCount
		if byteCount < takenByteCount {
			break
		}
	}
	return taken
}

// The deposit a plan sends: its entries' RecordDeposits in seq order, marshaled once per attempt, deterministically,
// so a retry in this process carries the same batch.
func (self *recordWriter) depositOf(plan *recordPushPlan) (*RecordStreamDeposit, error) {
	entries := func() map[uint64]*RecordSealedEntry {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.queueWithLock(plan.LogId).planSeqEntries
	}()
	batch := &protocol.RecordDepositBatch{}
	for _, seq := range plan.ownSeqs() {
		sealed := entries[seq]
		if sealed == nil {
			return nil, fmt.Errorf("%w: deposit plan of log %s names seq %d, which it does not hold", ErrRecordChainCorrupt, plan.LogId, seq)
		}
		batch.Entries = append(batch.Entries, sealed.Deposit())
	}
	batchBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
	for _, deposit := range batch.GetEntries() {
		clear(deposit.GetKey())
		clear(deposit.GetSalt())
	}
	if err != nil {
		return nil, fmt.Errorf("record: deposit batch: %w", err)
	}
	return &RecordStreamDeposit{
		PushId:             plan.PushId,
		DepositorSidecarId: self.sidecarId,
		DepositId:          plan.DepositId,
		Batch:              batchBytes,
		AuthPin:            plan.authPin(),
	}, nil
}

// One deposit's entries as an ingester reads them: each entry's stored bytes, its header's Signed bytes and sealed
// body, and the key and salt to re-slot.
type RecordDepositedEntry struct {
	Entry      []byte
	Signed     []byte
	SealedBody []byte
	Key        []byte
	Salt       []byte
}

// Parses a deposit batch as section 5.4 shapes it, keeping each entry's stored bytes: at most 64 entries, within
// byteCount unless one entry alone, each a RecordEntry with no slot fields and a 32-byte key and salt. Any failure is
// ErrRecordDepositInvalid, the whole deposit consumed unrecorded (section 5.4's parse step). testHookSecret sees each
// key and salt: the batch is the ingester's unwrap of them.
func RecordDepositBatchParse(batchBytes []byte, byteCount int) ([]*RecordDepositedEntry, error) {
	batch := &protocol.RecordDepositBatch{}
	if err := proto.Unmarshal(batchBytes, batch); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordDepositInvalid, err)
	}
	if len(batch.GetEntries()) == 0 || recordDepositEntryCount < len(batch.GetEntries()) {
		return nil, fmt.Errorf("%w: %d entries", ErrRecordDepositInvalid, len(batch.GetEntries()))
	}
	if 1 < len(batch.GetEntries()) && byteCount < len(batchBytes) {
		return nil, fmt.Errorf("%w: %d entries in %d bytes", ErrRecordDepositInvalid, len(batch.GetEntries()), len(batchBytes))
	}
	deposited := make([]*RecordDepositedEntry, 0, len(batch.GetEntries()))
	for _, deposit := range batch.GetEntries() {
		if len(deposit.GetKey()) != RecordKeyByteCount || len(deposit.GetSalt()) != RecordSaltByteCount {
			return nil, fmt.Errorf("%w: a key of %d bytes and a salt of %d", ErrRecordDepositInvalid, len(deposit.GetKey()), len(deposit.GetSalt()))
		}
		testHookSecret("record_entry_key", deposit.GetKey())
		testHookSecret("record_entry_salt", deposit.GetSalt())
		fields := &recordEntryFields{}
		if err := fields.parse(deposit.GetEntry()); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRecordDepositInvalid, err)
		}
		if len(fields.keySlotId) != 0 || fields.keyIndex != 0 {
			return nil, fmt.Errorf("%w: a deposited entry names a slot", ErrRecordDepositInvalid)
		}
		deposited = append(deposited, &RecordDepositedEntry{
			Entry:      bytes.Clone(deposit.GetEntry()),
			Signed:     fields.signed,
			SealedBody: fields.sealedBody,
			Key:        bytes.Clone(deposit.GetKey()),
			Salt:       bytes.Clone(deposit.GetSalt()),
		})
	}
	return deposited, nil
}
