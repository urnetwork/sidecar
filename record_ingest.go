// RECORD.md section 5.4's ingest, on every leg: a device with rw on a log, for a vault a consented device of its
// author (§11.12), takes each deposit ref's deposits in version order and writes what passes into its own stream, since
// an owned stream takes only its sidecar's pushes (§11.8). An entry's bytes and its writer's chain stay as written:
// only key_slot_id and key_index change, to a row of the ingester's next push's slot object (record_slot.go's
// recordEntryReslot). Several ingesters may run.
//
//	1 parse   a batch or entry that does not parse: consumed unrecorded, bad_entry
//	2 signer  the header verifies under its writer's identity key as section 5.5's does, the writer is the deposit
//	          ref's sidecar and log_id this log: else consumed unrecorded, bad_entry
//	3 right   the writer could deposit here at the deposit push's own pin, never this ingester's; policy_version does
//	          not pass that pin; no compromise revocation from a since_n at or before it; and no log entry after it
//	          ended the right more than TimeSkewTimeout before the push's time_ms: else consumed unrecorded, bad_entry
//	4 body    opened with the deposit's key and its commitment recomputed: else consumed unrecorded, bad_entry
//	5 class   a receipt-only depositor's entry is a read of source observed: else consumed unrecorded,
//	          depositor_kind (§11.12)
//	6 erased  an entry an erasure names: consumed unrecorded, so a spool re-uploaded after a site loss or a late
//	          deposit brings no erased body back
//	7 chain   a gap or fork is kept, never dropped: readers alarm on it (section 5.5), and nothing here judges it
//	8 write   a new slot row, then the entry in the ingester's next push, unless its stream holds the leaf already;
//	          once each entry of a deposit is written or refused, one CONSUME covers it
//
// No entry's outcome holds the ref back: a deposit waiting for its write is consumed by a later pass, after the
// writer's commit. A kill between the write's commit and the CONSUME leaves the deposit, and the next pass finds the
// leaf in this ingester's stream and only consumes. A CONSUME of a deposit another ingester consumed first answers
// PATH_CONFLICT, which reads as consumed. Two ingesters may each hold a copy of one entry, in their own streams under
// their own rows with the same key and salt, and readers show one by leaf, every copy kept (record_reader.go).
//
// ERASE notes are sealed and their format is EVS1-M2-30's and RECORD-M3-06's: until those land, step 6 knows an
// erasure by the erasure entries and erased copies this device's reader holds.
//
// Safe for concurrent use: one pass at a time.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// This sidecar may not ingest the log: it has no rw there as a consented device (§11.12).
var ErrRecordNotIngester = errors.New("record log not ingested by this sidecar")

// A log's ingester on this device, over the record's writer and reader.
type RecordIngester struct {
	sidecarId Id
	writer    *recordWriter
	reader    *RecordReader
	alarm     func(alarm *RecordAlarm)
	settings  *SidecarRecordSettings
	log       Logger

	ingestLock sync.Mutex
}

// An ingester writing through writer and judging copies by reader, which share their bindings.
func newRecordIngester(writer *recordWriter, reader *RecordReader) *RecordIngester {
	return &RecordIngester{
		sidecarId: writer.sidecarId,
		writer:    writer,
		reader:    reader,
		alarm:     writer.alarm,
		settings:  writer.settings,
		log:       writer.log,
	}
}

// One alarm through the record's sink.
func (self *RecordIngester) raise(reason SidecarRecordAlarm, logId Id, sidecarId Id) {
	if self.alarm != nil {
		self.alarm(&RecordAlarm{Reason: reason, LogId: logId, SidecarId: &sidecarId})
	}
}

// One pass over logId's deposit refs: each deposit's entries written or refused, and each settled deposit consumed.
// The first failure to read or consume stops the pass, keeping what it did.
func (self *RecordIngester) Ingest(ctx context.Context, logId Id) error {
	self.ingestLock.Lock()
	defer self.ingestLock.Unlock()
	auth := self.writer.auth()
	if !auth.Consented(logId, self.sidecarId) || !auth.Writes(logId, self.sidecarId) {
		return fmt.Errorf("%w: %s", ErrRecordNotIngester, logId)
	}
	// what the log's streams hold, this ingester's own among them, so a leaf already written is found
	if err := self.reader.Sync(ctx, logId); err != nil {
		return err
	}
	streams := self.writer.boundStreams()
	refs, err := streams.DepositRefs(ctx, logId)
	if err != nil {
		return err
	}
	slices.SortFunc(refs, func(a *RecordStreamHead, b *RecordStreamHead) int { return a.SidecarId.Cmp(b.SidecarId) })
	for _, ref := range refs {
		deposits, err := streams.ReadDeposits(ctx, logId, ref.SidecarId)
		if err != nil {
			return err
		}
		settled := []Id{}
		for _, deposit := range deposits {
			done := self.ingestDeposit(auth, logId, ref.SidecarId, deposit)
			if done {
				settled = append(settled, deposit.DepositId)
			}
		}
		if len(settled) == 0 {
			continue
		}
		pushId, err := self.writer.drawId()
		if err != nil {
			return err
		}
		consume := &RecordStreamConsume{PushId: pushId, DepositorSidecarId: ref.SidecarId, DepositIds: settled}
		testHookBarrier("record.consume.before", recordChainIdText(logId))
		_, err = streams.Consume(ctx, logId, consume)
		testHookBarrier("record.consume.after", recordChainIdText(logId))
		if code, ok := RecordStreamRefusalCode(err); ok && code == protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT {
			// another ingester consumed one first: each is consumed now, the rest by a later pass
			err = nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// Steps 1 to 8 for one deposit: true once every entry is written or refused, so the deposit may be consumed.
func (self *RecordIngester) ingestDeposit(auth RecordAuthView, logId Id, depositorId Id, deposit *RecordStreamDepositVersion) bool {
	entries, err := RecordDepositBatchParse(deposit.Batch, self.settings.DepositByteCount)
	if err != nil {
		self.raise(SidecarRecordAlarmBadEntry, logId, depositorId)
		return true
	}
	pinView, err := auth.At(deposit.AuthPin)
	if errors.Is(err, ErrRecordAuthAhead) {
		// judged once this state reaches the deposit's pin
		return false
	}
	if err != nil {
		self.raise(SidecarRecordAlarmBadEntry, logId, depositorId)
		return true
	}
	done := true
	for _, entry := range entries {
		outcome := self.ingestEntry(auth, pinView, logId, depositorId, deposit, entry)
		done = done && outcome
	}
	return done
}

// Steps 2 to 8 for one deposited entry: true once it is written or refused.
func (self *RecordIngester) ingestEntry(auth RecordAuthView, pinView RecordAuthView, logId Id, depositorId Id, deposit *RecordStreamDepositVersion, entry *RecordDepositedEntry) bool {
	header, signed, err := recordSignedHeader(entry.Signed)
	if err != nil {
		self.raise(SidecarRecordAlarmBadEntry, logId, depositorId)
		return true
	}
	writerId := recordIdOf(header.Header.GetWriterSidecarId())
	// 2 signer
	if writerId != depositorId || !bytes.Equal(signed.GetSignerId(), writerId[:]) || !bytes.Equal(header.Header.GetLogId(), logId[:]) ||
		signed.GetType() != uint32(bridge.SignedType_SIGNED_RECORD_HEADER) {
		self.raise(SidecarRecordAlarmBadEntry, logId, depositorId)
		return true
	}
	key := pinView.IdentityKey(writerId)
	if len(key) == 0 || bridge.VerifySigned(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, key) != nil {
		self.raise(SidecarRecordAlarmBadEntry, logId, depositorId)
		return true
	}
	// 3 right, at the deposit's own pin
	pinVersion := deposit.AuthPin.GetVersion()
	rightHeld := pinView.Deposits(logId, writerId) && header.Header.GetPolicyVersion() <= pinVersion
	if since, compromised := auth.CompromisedSince(writerId); compromised && since <= pinVersion {
		rightHeld = false
	}
	if endMillis, ended := auth.RightEnded(logId, writerId, pinVersion); ended &&
		time.Duration(deposit.TimeMillis-endMillis)*time.Millisecond > self.settings.TimeSkewTimeout {
		rightHeld = false
	}
	if !rightHeld {
		self.raise(SidecarRecordAlarmBadEntry, logId, depositorId)
		return true
	}
	// 4 body
	body, err := RecordOpen(header, entry.SealedBody, entry.Key, entry.Salt)
	if err != nil {
		self.raise(SidecarRecordAlarmBadEntry, logId, depositorId)
		return true
	}
	clear(body)
	// 5 class
	if pinView.ReceiptOnly(logId, writerId) &&
		(header.Kind() != RecordKindRead || RecordSource(header.Header.GetSource()) != RecordSourceObserved) {
		self.raise(SidecarRecordAlarmDepositorKind, logId, depositorId)
		return true
	}
	// 6 erased
	if self.reader.Erased(logId, recordIdOf(header.Header.GetEntryId())) {
		return true
	}
	// 8 write, unless this ingester's stream holds the leaf already
	leaf := header.LeafHash()
	if self.reader.HoldsIn(logId, self.sidecarId, leaf) {
		return true
	}
	self.writer.enqueueIngested(logId, &recordIngestedEntry{
		entry:       entry.Entry,
		key:         entry.Key,
		salt:        entry.Salt,
		header:      header,
		depositorId: depositorId,
		depositId:   deposit.DepositId,
	})
	return false
}

// Queues an ingested entry for logId's next push, unless one with its leaf waits or is planned already.
func (self *recordWriter) enqueueIngested(logId Id, ingested *recordIngestedEntry) {
	leaf := ingested.header.LeafHash()
	queued := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(logId)
		for _, waiting := range queue.waitingIngested {
			if waiting.header.LeafHash() == leaf {
				return false
			}
		}
		if queue.plan != nil {
			for _, planEntry := range queue.plan.Entries {
				if planEntry.Ingested == nil {
					continue
				}
				if signedBytes, _, err := recordEntrySplit(planEntry.Ingested.Entry); err == nil {
					if header, _, err := recordSignedHeader(signedBytes); err == nil && header.LeafHash() == leaf {
						return false
					}
				}
			}
		}
		if !queue.waitingWithLock() {
			queue.firstWaitingMillis = self.clock.Now().UnixMilli()
		}
		queue.waitingIngested = append(queue.waitingIngested, ingested)
		return true
	}()
	if queued {
		self.signal()
	}
}
