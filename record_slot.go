// The writer's plans and slots, on every leg: what a push or deposit will carry, journaled before it first goes, and
// the stream's counter. In the record component's sealed directory:
//
//	push/<log_id>     the one plan outstanding for the log: its push id, its slot id or deposit id, the pin it
//	                  declares, and each entry's place, a stream path and key index, or a seq for a deposit
//	stream/<log_id>   the newest counter this writer's stream holds, which a commit raises
//
// A plan names this writer's own entries by seq, whose bytes and keys the chain's journal holds until the commit is
// acknowledged, and carries an ingested entry whole, its bytes, key and salt (RECORD-M3-04), since the deposit it came
// from is consumed only after. Push, slot and deposit ids are random per push statement (§11.6): a retry of the plan
// keeps them, and a plan built again after a refusal draws new ones. A slot object holds one row a key, key || salt,
// 64 B, at its key_index, 0 for the first entry of the push, so 64 rows wrapped at 104 B stay inside 8 KiB (§16.8).
//
// The stream's counter, from 1, names each entry's path (record_route.go); in a stream that holds no ingested entry it
// equals seq. A counter the file has lost, or one evs refused the paths of, is read back from the stream itself: the
// newest push holds the highest, since every plan takes the next ones in order.
//
// Safe for concurrent use, through the writer's locks.

package sidecar

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The plan and counter files' format values.
const (
	recordPlanDirectory    = "push"
	recordCounterDirectory = "stream"
	recordPlanVersion      = 1
	recordCounterVersion   = 1
)

// One push or deposit, planned for a log.
type recordPushPlan struct {
	Version int  `json:"version"`
	LogId   Id   `json:"log_id"`
	Deposit bool `json:"deposit"`
	PushId  Id   `json:"push_id"`
	// a stream push's slot object
	SlotId Id `json:"slot_id"`
	// a deposit's id in its ref
	DepositId  Id     `json:"deposit_id"`
	PinVersion uint64 `json:"pin_version"`
	PinChain   []byte `json:"pin_chain"`
	// in the push's order: (writer, seq)
	Entries []*recordPlanEntry `json:"entries"`
}

// One entry's place in a plan.
type recordPlanEntry struct {
	// this writer's own entry, by its seq in the journal; 0 for an ingested one
	Seq      uint64              `json:"seq,omitempty"`
	Ingested *recordPlanIngested `json:"ingested,omitempty"`
	// a stream push's path and key index
	Path     string `json:"path,omitempty"`
	Counter  uint64 `json:"counter,omitempty"`
	KeyIndex uint32 `json:"key_index"`
}

// An ingested entry as a plan carries it: its RecordEntry bytes as deposited, its key and salt, and the deposit.
type recordPlanIngested struct {
	Entry       []byte `json:"entry"`
	Key         []byte `json:"key"`
	Salt        []byte `json:"salt"`
	DepositorId Id     `json:"depositor_id"`
	DepositId   Id     `json:"deposit_id"`
}

// One entry an ingester hands the writer (RECORD-M3-04): verified, its body opened, its bytes as deposited.
type recordIngestedEntry struct {
	entry       []byte
	key         []byte
	salt        []byte
	header      *StoredRecordHeader
	depositorId Id
	depositId   Id
}

// The waiting form of a planned ingested entry, parsed again, for a plan refused before it committed. False for one
// that no longer parses, which the caller drops: its deposit is still unconsumed, so the next ingest takes it again.
func (self *recordPlanIngested) entry() (*recordIngestedEntry, bool) {
	signedBytes, _, err := recordEntrySplit(self.Entry)
	if err != nil {
		return nil, false
	}
	header, _, err := recordSignedHeader(signedBytes)
	if err != nil {
		return nil, false
	}
	return &recordIngestedEntry{
		entry:       bytes.Clone(self.Entry),
		key:         bytes.Clone(self.Key),
		salt:        bytes.Clone(self.Salt),
		header:      header,
		depositorId: self.DepositorId,
		depositId:   self.DepositId,
	}, true
}

// The plan's own seqs, ascending.
func (self *recordPushPlan) ownSeqs() []uint64 {
	seqs := []uint64{}
	for _, entry := range self.Entries {
		if entry.Ingested == nil {
			seqs = append(seqs, entry.Seq)
		}
	}
	slices.Sort(seqs)
	return seqs
}

// The highest stream counter the plan takes, 0 for a deposit.
func (self *recordPushPlan) lastCounter() uint64 {
	var counter uint64
	for _, entry := range self.Entries {
		counter = max(counter, entry.Counter)
	}
	return counter
}

// The plan file of a log.
func recordPlanName(logId Id) string {
	return recordPlanDirectory + "/" + recordChainIdText(logId)
}

// The counter file of a log.
func recordCounterName(logId Id) string {
	return recordCounterDirectory + "/" + recordChainIdText(logId)
}

// Every journaled plan, refusing one that does not decode or whose name is not its log's.
func (self *recordWriter) readPlans() ([]*recordPushPlan, error) {
	entries, err := self.store.List(recordPlanDirectory + "/")
	if err != nil {
		return nil, err
	}
	plans := []*recordPushPlan{}
	for _, entry := range entries {
		content, err := self.chain.readFile(entry.Name)
		if err != nil {
			return nil, err
		}
		plan := &recordPushPlan{}
		if err := recordChainDecode(content, plan); err != nil || plan.Version != recordPlanVersion || recordPlanName(plan.LogId) != entry.Name {
			return nil, fmt.Errorf("%w: plan %s", ErrRecordChainCorrupt, entry.Name)
		}
		plans = append(plans, plan)
	}
	return plans, nil
}

// The counter file's document.
type recordCounterDocument struct {
	Version int    `json:"version"`
	LogId   Id     `json:"log_id"`
	Counter uint64 `json:"counter"`
}

// Raises the log's counter file to counter, durably.
func (self *recordWriter) writeCounter(logId Id, counter uint64) error {
	content, err := json.Marshal(&recordCounterDocument{Version: recordCounterVersion, LogId: logId, Counter: counter})
	if err != nil {
		return err
	}
	if err := self.chain.writeFile(recordCounterName(logId), content); err != nil {
		return fmt.Errorf("record: counter: %w", err)
	}
	return nil
}

// The log's counter: the queue's, the file's, or read back from this writer's own stream.
func (self *recordWriter) loadCounter(ctx context.Context, logId Id) (uint64, error) {
	counter, loaded := func() (uint64, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(logId)
		return queue.counter, queue.counterLoaded
	}()
	if loaded {
		return counter, nil
	}
	content, err := self.chain.readFile(recordCounterName(logId))
	if err != nil {
		return 0, err
	}
	var fileCounter uint64
	if content != nil {
		document := &recordCounterDocument{}
		if err := recordChainDecode(content, document); err != nil || document.Version != recordCounterVersion || document.LogId != logId {
			return 0, fmt.Errorf("%w: counter of log %s", ErrRecordChainCorrupt, logId)
		}
		fileCounter = document.Counter
	}
	streamCounter, err := RecordStreamCounter(ctx, self.boundStreams(), logId, self.sidecarId)
	if err != nil {
		return 0, err
	}
	counter = max(fileCounter, streamCounter)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	queue := self.queueWithLock(logId)
	queue.counter = max(queue.counter, counter)
	queue.counterLoaded = true
	return queue.counter, nil
}

// The highest counter writerSidecarId's own stream of logId holds, from its newest push, 0 for a stream with none.
func RecordStreamCounter(ctx context.Context, streams RecordStreams, logId Id, writerSidecarId Id) (uint64, error) {
	heads, err := streams.Streams(ctx, logId)
	if err != nil {
		return 0, err
	}
	var newest uint64
	for _, head := range heads {
		if head.SidecarId == writerSidecarId {
			newest = head.Version
		}
	}
	if newest == 0 {
		return 0, nil
	}
	versions, err := streams.ReadStream(ctx, logId, writerSidecarId, newest-1)
	if err != nil {
		return 0, err
	}
	var counter uint64
	for _, version := range versions {
		for _, entry := range version.Entries {
			if n, ok := RecordStreamPathCounter(entry.Path); ok {
				counter = max(counter, n)
			}
		}
	}
	return counter, nil
}

// 16 random bytes as an Id: a push, slot or deposit id, drawn per push statement.
func (self *recordWriter) drawId() (Id, error) {
	random := self.random
	if random == nil {
		random = cryptorand.Reader
	}
	var id Id
	if _, err := io.ReadFull(random, id[:]); err != nil {
		return Id{}, fmt.Errorf("record: draw: %w", err)
	}
	return id, nil
}

// Takes the next batch of logId's waiting entries into a plan and journals it, or answers nil when none can go now.
// Own entries go in seq order from the lowest, so the chain reaches evs in order.
func (self *recordWriter) buildPlan(ctx context.Context, auth RecordAuthView, logId Id, deposit bool) (*recordPushPlan, error) {
	pin := auth.Pin()
	if pin == nil {
		return nil, fmt.Errorf("record: no auth pin to declare")
	}
	var counter uint64
	if !deposit {
		loaded, err := self.loadCounter(ctx, logId)
		if err != nil {
			return nil, err
		}
		counter = loaded
	}
	pushId, err := self.drawId()
	if err != nil {
		return nil, err
	}
	placeId, err := self.drawId()
	if err != nil {
		return nil, err
	}
	plan := &recordPushPlan{
		Version:    recordPlanVersion,
		LogId:      logId,
		Deposit:    deposit,
		PushId:     pushId,
		PinVersion: pin.GetVersion(),
		PinChain:   bytes.Clone(pin.GetChain()),
	}
	if deposit {
		plan.DepositId = placeId
	} else {
		plan.SlotId = placeId
	}

	// take entries alone, so no seal lands between a seq taken and the next one left
	self.sealLock.Lock()
	taken, takenIngested := func() ([]*RecordSealedEntry, []*recordIngestedEntry) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		queue := self.queueWithLock(logId)
		seqs := make([]uint64, 0, len(queue.waitingSeqEntries))
		for seq := range queue.waitingSeqEntries {
			seqs = append(seqs, seq)
		}
		slices.Sort(seqs)
		taken := []*RecordSealedEntry{}
		takenIngested := []*recordIngestedEntry{}
		if deposit {
			taken = recordDepositTake(queue, seqs, self.settings.DepositByteCount)
		} else {
			limit := recordPushEntryCount(self.settings)
			for _, seq := range seqs {
				if limit <= len(taken) {
					break
				}
				taken = append(taken, queue.waitingSeqEntries[seq])
			}
			for _, ingested := range queue.waitingIngested {
				if limit <= len(taken)+len(takenIngested) {
					break
				}
				takenIngested = append(takenIngested, ingested)
			}
		}
		for _, entry := range taken {
			delete(queue.waitingSeqEntries, entry.Seq)
			queue.planSeqEntries[entry.Seq] = entry
		}
		queue.waitingIngested = queue.waitingIngested[len(takenIngested):]
		return taken, takenIngested
	}()
	self.sealLock.Unlock()
	if len(taken)+len(takenIngested) == 0 {
		return nil, nil
	}

	type candidate struct {
		header   *StoredRecordHeader
		own      *RecordSealedEntry
		ingested *recordIngestedEntry
	}
	candidates := []*candidate{}
	for _, entry := range taken {
		header, err := entry.Header()
		if err != nil {
			self.restoreTaken(logId, taken, takenIngested)
			return nil, err
		}
		candidates = append(candidates, &candidate{header: header, own: entry})
	}
	for _, ingested := range takenIngested {
		candidates = append(candidates, &candidate{header: ingested.header, ingested: ingested})
	}
	// §16.8's order row: by writer, then seq, whatever the statement's token order
	slices.SortStableFunc(candidates, func(a *candidate, b *candidate) int {
		return RecordCompareInPush(a.header, b.header)
	})
	for index, candidate := range candidates {
		planEntry := &recordPlanEntry{}
		if candidate.own != nil {
			planEntry.Seq = candidate.own.Seq
		} else {
			planEntry.Ingested = &recordPlanIngested{
				Entry:       candidate.ingested.entry,
				Key:         candidate.ingested.key,
				Salt:        candidate.ingested.salt,
				DepositorId: candidate.ingested.depositorId,
				DepositId:   candidate.ingested.depositId,
			}
		}
		if !deposit {
			planEntry.Counter = counter + uint64(index) + 1
			path, err := RecordStreamPath(planEntry.Counter)
			if err != nil {
				self.restoreTaken(logId, taken, takenIngested)
				return nil, err
			}
			planEntry.Path = path
			planEntry.KeyIndex = uint32(index)
		}
		plan.Entries = append(plan.Entries, planEntry)
	}
	content, err := json.Marshal(plan)
	if err == nil {
		testHookBarrier("record.plan.before", recordChainIdText(logId))
		err = self.chain.writeFile(recordPlanName(logId), content)
		testHookBarrier("record.plan.after", recordChainIdText(logId))
	}
	clear(content)
	if err != nil {
		self.restoreTaken(logId, taken, takenIngested)
		return nil, fmt.Errorf("record: plan: %w", err)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.queueWithLock(logId).plan = plan
	return plan, nil
}

// Returns entries a plan took to the waiting set, when the plan was never journaled.
func (self *recordWriter) restoreTaken(logId Id, taken []*RecordSealedEntry, takenIngested []*recordIngestedEntry) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	queue := self.queueWithLock(logId)
	for _, entry := range taken {
		delete(queue.planSeqEntries, entry.Seq)
		queue.waitingSeqEntries[entry.Seq] = entry
	}
	queue.waitingIngested = append(slices.Clone(takenIngested), queue.waitingIngested...)
}

// A RecordEntry's fields as stored (§16.8), read from its wire form so neither the header's Signed nor sealed_body is
// re-encoded: what a reader verifies, and what an ingester re-slots with every other byte as it came.
type recordEntryFields struct {
	signed     []byte
	sealedBody []byte
	keySlotId  []byte
	keyIndex   uint32
	version    uint32
	// every field but key_slot_id and key_index, as stored, in order
	kept []byte
}

// Reads entryBytes field by field, refusing a field repeated, a known field in another wire type, and an entry with
// no header: a repeated header would merge two Signed messages, and which bytes were signed would be unclear.
func (self *recordEntryFields) parse(entryBytes []byte) error {
	seen := map[protowire.Number]bool{}
	for rest := entryBytes; 0 < len(rest); {
		number, wireType, tagLength := protowire.ConsumeTag(rest)
		if tagLength < 0 {
			return fmt.Errorf("%w: a record entry's tag", ErrRecordStoredInvalid)
		}
		valueLength := protowire.ConsumeFieldValue(number, wireType, rest[tagLength:])
		if valueLength < 0 {
			return fmt.Errorf("%w: a record entry's field %d", ErrRecordStoredInvalid, number)
		}
		field := rest[:tagLength+valueLength]
		value := rest[tagLength : tagLength+valueLength]
		rest = rest[tagLength+valueLength:]
		switch number {
		case recordEntryHeaderField, recordEntrySealedBodyField, recordEntryKeySlotIdField:
			if wireType != protowire.BytesType || seen[number] {
				return fmt.Errorf("%w: a record entry's field %d twice or not bytes", ErrRecordStoredInvalid, number)
			}
			content, _ := protowire.ConsumeBytes(value)
			switch number {
			case recordEntryHeaderField:
				self.signed = bytes.Clone(content)
			case recordEntrySealedBodyField:
				self.sealedBody = bytes.Clone(content)
			default:
				self.keySlotId = bytes.Clone(content)
			}
		case recordEntryVersionField, recordEntryKeyIndexField:
			if wireType != protowire.VarintType || seen[number] {
				return fmt.Errorf("%w: a record entry's field %d twice or not a varint", ErrRecordStoredInvalid, number)
			}
			varint, _ := protowire.ConsumeVarint(value)
			if varint > uint64(^uint32(0)) {
				return fmt.Errorf("%w: a record entry's field %d past 32 bits", ErrRecordStoredInvalid, number)
			}
			if number == recordEntryVersionField {
				self.version = uint32(varint)
			} else {
				self.keyIndex = uint32(varint)
			}
		}
		seen[number] = true
		if number != recordEntryKeySlotIdField && number != recordEntryKeyIndexField {
			self.kept = append(self.kept, field...)
		}
	}
	if self.signed == nil {
		return fmt.Errorf("%w: a record entry with no header", ErrRecordStoredInvalid)
	}
	return nil
}

// The RecordEntry's stored Signed bytes and sealed_body.
func recordEntrySplit(entryBytes []byte) ([]byte, []byte, error) {
	entry := &recordEntryFields{}
	if err := entry.parse(entryBytes); err != nil {
		return nil, nil, err
	}
	return entry.signed, entry.sealedBody, nil
}

// entryBytes with its key_slot_id and key_index set to name another slot's row, every other field as it came: an
// ingester's copy of a deposited entry in its own stream (RECORD.md section 5.4's stream row). slotId nil and keyIndex 0
// leave the slot fields out, as a deposit's are.
func recordEntryReslot(entryBytes []byte, slotId *Id, keyIndex uint32) ([]byte, error) {
	entry := &recordEntryFields{}
	if err := entry.parse(entryBytes); err != nil {
		return nil, err
	}
	reslotted := bytes.Clone(entry.kept)
	if slotId != nil {
		reslotted = protowire.AppendTag(reslotted, recordEntryKeySlotIdField, protowire.BytesType)
		reslotted = protowire.AppendBytes(reslotted, slotId[:])
	}
	if keyIndex != 0 {
		reslotted = protowire.AppendTag(reslotted, recordEntryKeyIndexField, protowire.VarintType)
		reslotted = protowire.AppendVarint(reslotted, uint64(keyIndex))
	}
	return reslotted, nil
}

// The header a Signed's stored bytes carry, checked as ParseStoredRecordHeader checks it, and that Signed.
func recordSignedHeader(signedBytes []byte) (*StoredRecordHeader, *bridge.Signed, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(signedBytes, signed); err != nil {
		return nil, nil, fmt.Errorf("%w: a header's Signed: %v", ErrRecordStoredInvalid, err)
	}
	header, err := ParseStoredRecordHeader(signed.GetBody())
	if err != nil {
		return nil, nil, err
	}
	return header, signed, nil
}
