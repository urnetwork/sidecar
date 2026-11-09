// §16.8's read receipts (D-MCP-18, R-TRUST-7), on every leg. A reader of an owner-bound repo that is not its writer,
// an EvsShare subject or, from M6, a Team's audit reader, deposits a read entry to the repo's drop key and awaits evs's
// 200 before it decrypts any object the read names. Deposit is that step, which EVS1-M3-01's read gate, ACL-M3-01 and
// SEARCH-M10-27 call. It returns nil only once every object the read names is covered by a receipt evs committed, so
// a refusal, an unreachable evs or a lost answer refuses the read: a journal entry proves nothing to the author, and a
// first read that cannot deposit is refused. Once it returns, the read's GETs may run in parallel.
//
//	entry     RecordHeader kind read, source observed, with no run, agent or action id, which are the reader's own;
//	          tainted by section 5.3's closed rule from the request's run; ReadBody{object ids <= 64, purpose} with
//	          read_log_id empty (the audit reader's second receipt, to T, is RECORD-M6-04's); one entry a deposit,
//	          within §11.12's 4 KiB
//	chain     the writer's chain store: a receipt takes this sidecar's next seq in the repo, sealed and journaled as
//	          any entry (record_seal.go), never through Append, and the writer's push loop leaves journaled read
//	          entries to this path (record_writer.go's load)
//	order     one Deposit at a time a log, and a receipt sealed earlier and not yet committed goes again before a new
//	          one is sealed, so a log's receipts reach evs in seq order; a read that cannot land the older one is
//	          refused too
//	scope     evs takes it at the deposit scope of the reader's token, repo:<id>:deposit (§7.8), on the reader's own
//	          deposit ref; a sidecar the state does not let deposit there seals nothing, and its read is refused
//	budget    evs's 429, past 256 a UTC day per repo or 4 KiB a deposit, refuses the read; the receipt stays as it is
//	          and goes first next time (§11.12)
//	offline   nothing waits for the author: its devices ingest receipts whenever they run (record_ingest.go)
//
// What was receipted is kept in the record component's sealed directory, one file a receipt:
//
//	receipt/<log_id>/<seq>   the push id, deposit id and pin of the receipt's deposit, drawn once and written before
//	                         its first send, so a retry is the same statement and evs answers the commit it made; its
//	                         purpose and object ids; and, once evs committed it, the UTC day
//
// A receipt's file is written after its journal record and before its first send, and marked committed before its
// journal record is acknowledged. So a kill anywhere leaves one of three states: a journaled read entry with no file,
// never sent, which takes fresh ids at the next load; a pending file, which goes again as the same statement; or a
// committed file, whose objects read as receipted. A restart between a deposit and its read therefore deposits nothing
// twice. A committed receipt's objects count as receipted for the rest of its UTC day on this device's clock, the
// budget's window, so a read of one of them that day deposits nothing, and its file goes with the day. A refusal that
// spends the push id (codes below 128) draws a new push id and deposit id for the next send, and re-signs nothing,
// as the writer's rebuilt plans do (record_batch.go).
//
// Barriers: record.receipt.deposit.before and .after around each send, keyed by the log, with no state lock held.
//
// Safe for concurrent use: one log's deposits go one at a time, different logs' side by side.

package sidecar

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The receipt files' format values.
const (
	recordReceiptDirectory = "receipt"
	recordReceiptVersion   = 1
)

// ReadBody.purpose (RECORD.md section 6.4): what the read a receipt covers was for. 0 is never written.
type RecordReadPurpose uint32

const (
	RecordReadPurposeRead       RecordReadPurpose = 1
	RecordReadPurposeSearch     RecordReadPurpose = 2
	RecordReadPurposeExport     RecordReadPurpose = 3
	RecordReadPurposeDisclosure RecordReadPurpose = 4
)

// Whether section 6.4 names the purpose.
func (self RecordReadPurpose) Known() bool {
	return RecordReadPurposeRead <= self && self <= RecordReadPurposeDisclosure
}

var (
	// A receipt request breaks a rule: no repo, a purpose section 6.4 does not name, or an object id that is neither
	// 16 nor 32 bytes. Nothing was sealed.
	ErrRecordReceiptInvalid = errors.New("record receipt invalid")
	// This sidecar may not deposit to the repo, so no receipt can land and the read is refused. Nothing was sealed.
	ErrRecordReceiptNotDepositor = errors.New("record receipt not depositable by this sidecar")
	// A receipt did not land: evs refused it, could not be reached, or its answer was lost. The read is refused; the
	// receipt, once sealed, goes again first at the next Deposit to its log.
	ErrRecordReceiptRefused = errors.New("record receipt not landed")
)

// One read a receipt covers, as a read gate asks for it.
type RecordReceiptRequest struct {
	// The owner-bound repo read, whose drop key takes the receipt: a vault, or another owner-bound repo, which is a
	// log only for its readers' receipts (RECORD.md section 4.1).
	RepoId  Id
	Purpose RecordReadPurpose
	// What the read decrypts: 16-byte ids, or 32-byte index files' content_sha256 (§11.14). Any number, 64 to a
	// receipt; one already receipted for this purpose this UTC day takes none.
	ObjectIds [][]byte
	// As RecordDraft's, for the receipt's taint alone: the run the read serves, nil for none, and whether no session
	// or harness ancestor asked for it. A nil RunId without NoSession seals the receipt tainted (section 5.3's unbound
	// row).
	RunId     *Id
	NoSession bool
}

// One object a receipt names, for one purpose.
type recordReceiptObject struct {
	purpose RecordReadPurpose
	id      string
}

// The request's objects after its own rules, each once, in the order asked.
func (self *RecordReceiptRequest) objects() ([]recordReceiptObject, error) {
	if self == nil || self.RepoId == (Id{}) {
		return nil, fmt.Errorf("%w: no repo", ErrRecordReceiptInvalid)
	}
	if !self.Purpose.Known() {
		return nil, fmt.Errorf("%w: purpose %d", ErrRecordReceiptInvalid, uint32(self.Purpose))
	}
	objects := []recordReceiptObject{}
	seen := map[recordReceiptObject]bool{}
	for _, objectId := range self.ObjectIds {
		if len(objectId) != recordIdByteCount && len(objectId) != recordHashByteCount {
			return nil, fmt.Errorf("%w: an object id of %d bytes", ErrRecordReceiptInvalid, len(objectId))
		}
		object := recordReceiptObject{purpose: self.Purpose, id: string(objectId)}
		if seen[object] {
			continue
		}
		seen[object] = true
		objects = append(objects, object)
	}
	return objects, nil
}

// One receipt's file.
type recordReceiptDocument struct {
	Version int    `json:"version"`
	LogId   Id     `json:"log_id"`
	Seq     uint64 `json:"seq"`
	// the entry's leaf, which its journal record must hold while it is pending
	Leaf       []byte `json:"leaf"`
	PushId     Id     `json:"push_id"`
	DepositId  Id     `json:"deposit_id"`
	PinVersion uint64 `json:"pin_version"`
	PinChain   []byte `json:"pin_chain"`
	Purpose    uint32 `json:"purpose"`
	// as the entry's ReadBody holds them
	ObjectIds [][]byte `json:"object_ids"`
	// the UTC day, time.DateOnly, on which evs's commit was taken; empty while pending
	CommittedDay string `json:"committed_day,omitempty"`
}

// The file of a log's receipt at seq.
func recordReceiptName(logId Id, seq uint64) string {
	return fmt.Sprintf("%s/%s/%0*d", recordReceiptDirectory, recordChainIdText(logId), recordChainSeqDigitCount, seq)
}

// A receipt file's document, held to itself and to the name it was read from.
func decodeRecordReceiptDocument(logId Id, name string, content []byte) (*recordReceiptDocument, error) {
	document := &recordReceiptDocument{}
	if err := recordChainDecode(content, document); err != nil {
		return nil, fmt.Errorf("%w: receipt %s: %v", ErrRecordChainCorrupt, name, err)
	}
	valid := document.Version == recordReceiptVersion && document.LogId == logId && document.Seq != 0 &&
		recordReceiptName(logId, document.Seq) == name && len(document.Leaf) == sha256.Size &&
		RecordReadPurpose(document.Purpose).Known() && 0 < len(document.ObjectIds) && len(document.ObjectIds) <= recordReadObjectCount
	for _, objectId := range document.ObjectIds {
		valid = valid && (len(objectId) == recordIdByteCount || len(objectId) == recordHashByteCount)
	}
	if document.CommittedDay != "" {
		_, err := time.Parse(time.DateOnly, document.CommittedDay)
		valid = valid && err == nil
	}
	if !valid {
		return nil, fmt.Errorf("%w: receipt %s is not this log's", ErrRecordChainCorrupt, name)
	}
	return document, nil
}

// The objects a receipt names.
func (self *recordReceiptDocument) objects() []recordReceiptObject {
	objects := make([]recordReceiptObject, 0, len(self.ObjectIds))
	for _, objectId := range self.ObjectIds {
		objects = append(objects, recordReceiptObject{purpose: RecordReadPurpose(self.Purpose), id: string(objectId)})
	}
	return objects
}

// A receipt sealed and not yet committed: its file's document, and its journaled entry with its key and salt.
type recordReceiptPending struct {
	document *recordReceiptDocument
	sealed   *RecordSealedEntry
}

// The deposit the receipt's file names: its one entry as a RecordDepositBatch, marshaled deterministically from the
// journaled bytes, so every send of one push id carries the same statement.
func (self *recordReceiptPending) deposit(depositorId Id) (*RecordStreamDeposit, error) {
	batch := &protocol.RecordDepositBatch{Entries: []*protocol.RecordDeposit{self.sealed.Deposit()}}
	batchBytes, err := proto.MarshalOptions{Deterministic: true}.Marshal(batch)
	for _, deposit := range batch.GetEntries() {
		clear(deposit.GetKey())
		clear(deposit.GetSalt())
	}
	if err != nil {
		return nil, fmt.Errorf("record receipt: batch: %w", err)
	}
	return &RecordStreamDeposit{
		PushId:             self.document.PushId,
		DepositorSidecarId: depositorId,
		DepositId:          self.document.DepositId,
		Batch:              batchBytes,
		AuthPin:            &bridge.AuthPin{Version: self.document.PinVersion, Chain: bytes.Clone(self.document.PinChain)},
	}, nil
}

// One log's receipts on this sidecar.
type recordReceiptLog struct {
	logId   Id
	hookKey string

	// One Deposit at a time on this log, held across its I/O, so the log's receipts go out in seq order. Every field
	// below is read and written only under it.
	depositLock sync.Mutex
	loaded      bool
	// the UTC day the fields below were loaded for
	day string
	// receipts sealed and not yet committed, by seq
	seqPendings map[uint64]*recordReceiptPending
	// what the day's committed receipts name
	receipted map[recordReceiptObject]bool
}

// The log's pending seqs, ascending.
func (self *recordReceiptLog) pendingSeqs() []uint64 {
	seqs := make([]uint64, 0, len(self.seqPendings))
	for seq := range self.seqPendings {
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)
	return seqs
}

// What of objects no committed receipt of the day covers.
func (self *recordReceiptLog) missing(objects []recordReceiptObject) []recordReceiptObject {
	missing := []recordReceiptObject{}
	for _, object := range objects {
		if !self.receipted[object] {
			missing = append(missing, object)
		}
	}
	return missing
}

// Drops what the log held in memory, wiping pending receipts' keys, for the next load to read again.
func (self *recordReceiptLog) unload() {
	for _, pending := range self.seqPendings {
		pending.sealed.Clear()
	}
	self.seqPendings = map[uint64]*recordReceiptPending{}
	self.receipted = map[recordReceiptObject]bool{}
	self.loaded = false
}

// §16.8's read receipts on one sidecar: the writer's chain, signer, store, clock and bindings, and each log's record
// of what was receipted. Safe for concurrent use.
type RecordReceipts struct {
	writer *recordWriter

	stateLock   sync.Mutex
	logReceipts map[Id]*recordReceiptLog
}

// The receipts of writer's sidecar, sharing its chains and bindings.
func newRecordReceipts(writer *recordWriter) *RecordReceipts {
	return &RecordReceipts{writer: writer, logReceipts: map[Id]*recordReceiptLog{}}
}

// The log's receipts, made on first use. Takes the state lock alone, and no I/O.
func (self *RecordReceipts) receiptLog(logId Id) *recordReceiptLog {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	receiptLog, ok := self.logReceipts[logId]
	if !ok {
		receiptLog = &recordReceiptLog{
			logId:       logId,
			hookKey:     recordChainIdText(logId),
			seqPendings: map[uint64]*recordReceiptPending{},
			receipted:   map[recordReceiptObject]bool{},
		}
		self.logReceipts[logId] = receiptLog
	}
	return receiptLog
}

// The UTC day now on the record's clock.
func (self *RecordReceipts) today() string {
	return self.writer.clock.Now().UTC().Format(time.DateOnly)
}

// Deposits read receipts for request's objects and returns once evs committed every one the day's receipts do not
// cover already: what a reader runs before it decrypts them. Any error refuses the read. ErrRecordReceiptInvalid and
// ErrRecordReceiptNotDepositor seal nothing; ErrRecordReceiptRefused wraps evs's answer, a RecordStreamRefusal when
// evs gave one. A read naming nothing new deposits nothing.
func (self *RecordReceipts) Deposit(ctx context.Context, request *RecordReceiptRequest) error {
	objects, err := request.objects()
	if err != nil {
		return err
	}
	if len(objects) == 0 {
		// a read that decrypts nothing needs no receipt
		return nil
	}
	receiptLog := self.receiptLog(request.RepoId)
	receiptLog.depositLock.Lock()
	defer receiptLog.depositLock.Unlock()
	if err := self.load(receiptLog); err != nil {
		return err
	}
	if len(receiptLog.missing(objects)) == 0 {
		return nil
	}
	// what was sealed before goes first, in seq order, so the log's chain reaches evs in order
	for _, seq := range receiptLog.pendingSeqs() {
		if err := self.send(ctx, receiptLog, receiptLog.seqPendings[seq]); err != nil {
			return err
		}
	}
	missing := receiptLog.missing(objects)
	for start := 0; start < len(missing); start += recordReadObjectCount {
		pending, err := self.seal(receiptLog, request, missing[start:min(start+recordReadObjectCount, len(missing))])
		if err != nil {
			return err
		}
		if err := self.send(ctx, receiptLog, pending); err != nil {
			return err
		}
	}
	return nil
}

// Reads the log's receipt files and its journal's read entries, once a UTC day: the day's committed receipts count as
// receipted and older ones' files go; a committed receipt still journaled is acknowledged now; a pending one keeps
// its ids; and a journaled read entry no file names, sealed before a kill could write its file, takes fresh ids. A
// file that does not decode, or a pending one with no journal record or another leaf, is ErrRecordChainCorrupt: the
// log's reads are refused rather than receipted on a guess.
func (self *RecordReceipts) load(receiptLog *recordReceiptLog) error {
	day := self.today()
	if receiptLog.loaded && receiptLog.day == day {
		return nil
	}
	receiptLog.unload()
	receiptLog.day = day
	documents, err := self.readDocuments(receiptLog.logId)
	if err != nil {
		return err
	}
	journaled, err := self.journaledReceipts(receiptLog.logId)
	if err != nil {
		return err
	}
	// what is left here at a return holds keys no pending receipt took
	defer func() {
		for _, sealed := range journaled {
			sealed.Clear()
		}
	}()
	for _, document := range documents {
		sealed, held := journaled[document.Seq]
		if held && !bytes.Equal(sealed.Leaf[:], document.Leaf) {
			receiptLog.unload()
			return fmt.Errorf("%w: receipt %d is not its journal record's entry", ErrRecordChainCorrupt, document.Seq)
		}
		if document.CommittedDay == "" {
			if !held {
				receiptLog.unload()
				return fmt.Errorf("%w: pending receipt %d has no journal record", ErrRecordChainCorrupt, document.Seq)
			}
			receiptLog.seqPendings[document.Seq] = &recordReceiptPending{document: document, sealed: sealed}
			delete(journaled, document.Seq)
			continue
		}
		if held {
			// marked before a kill could acknowledge it: committed, so it never goes again
			if err := self.writer.chain.Acknowledge(receiptLog.logId, []uint64{document.Seq}); err != nil {
				receiptLog.unload()
				return err
			}
			sealed.Clear()
			delete(journaled, document.Seq)
		}
		if document.CommittedDay != day {
			if err := self.writer.store.Remove(recordReceiptName(receiptLog.logId, document.Seq)); err != nil {
				self.writer.log.Warningf("[record]an old receipt's file stays until the next load: %s", err)
			}
			continue
		}
		for _, object := range document.objects() {
			receiptLog.receipted[object] = true
		}
	}
	seqs := make([]uint64, 0, len(journaled))
	for seq := range journaled {
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)
	for _, seq := range seqs {
		pending, err := self.adoptOrphan(journaled[seq])
		if err != nil {
			receiptLog.unload()
			return err
		}
		if err := self.writeDocument(pending.document); err != nil {
			receiptLog.unload()
			return err
		}
		receiptLog.seqPendings[seq] = pending
		delete(journaled, seq)
	}
	receiptLog.loaded = true
	return nil
}

// Every receipt file of the log, by seq.
func (self *RecordReceipts) readDocuments(logId Id) ([]*recordReceiptDocument, error) {
	entries, err := self.writer.store.List(recordReceiptDirectory + "/" + recordChainIdText(logId) + "/")
	if err != nil {
		return nil, err
	}
	documents := []*recordReceiptDocument{}
	for _, entry := range entries {
		content, err := self.writer.chain.readFile(entry.Name)
		if err != nil {
			return nil, err
		}
		if content == nil {
			// removed since the listing, as only a committed one of another day is
			continue
		}
		document, err := decodeRecordReceiptDocument(logId, entry.Name, content)
		if err != nil {
			return nil, err
		}
		documents = append(documents, document)
	}
	slices.SortFunc(documents, func(a *recordReceiptDocument, b *recordReceiptDocument) int {
		return cmp.Compare(a.Seq, b.Seq)
	})
	return documents, nil
}

// The log's journaled entries of kind read, by seq: receipts sealed and not yet acknowledged, each with its key and
// salt. The writer's own entries in the log, if it has any, are left to it.
func (self *RecordReceipts) journaledReceipts(logId Id) (map[uint64]*RecordSealedEntry, error) {
	entries, err := self.writer.chain.Pending(logId)
	if err != nil {
		return nil, err
	}
	receipts := map[uint64]*RecordSealedEntry{}
	for _, entry := range entries {
		if header, err := entry.Header(); err == nil && header.Kind() == RecordKindRead {
			receipts[entry.Seq] = entry
			continue
		}
		entry.Clear()
	}
	return receipts, nil
}

// A journaled read entry no file names: sealed before a kill could write its file, so never sent, it takes fresh ids
// and the pin now, its purpose and objects read back from its own body.
func (self *RecordReceipts) adoptOrphan(sealed *RecordSealedEntry) (*recordReceiptPending, error) {
	header, err := sealed.Header()
	if err != nil {
		return nil, fmt.Errorf("%w: receipt %d: %v", ErrRecordChainCorrupt, sealed.Seq, err)
	}
	opened, err := RecordOpen(header, sealed.SealedBody, sealed.Key, sealed.Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: receipt %d: %v", ErrRecordChainCorrupt, sealed.Seq, err)
	}
	body := &protocol.ReadBody{}
	if err := proto.Unmarshal(opened, body); err != nil || RecordBodyValidate(RecordKindRead, body) != nil {
		return nil, fmt.Errorf("%w: receipt %d's body", ErrRecordChainCorrupt, sealed.Seq)
	}
	pin := self.writer.auth().Pin()
	if pin == nil {
		return nil, fmt.Errorf("%w: no auth pin to declare", ErrRecordReceiptRefused)
	}
	return self.pendingOf(sealed, RecordReadPurpose(body.GetPurpose()), body.GetObjectIds(), pin)
}

// A pending receipt of sealed with fresh push and deposit ids, declaring pin. Nothing is written.
func (self *RecordReceipts) pendingOf(sealed *RecordSealedEntry, purpose RecordReadPurpose, objectIds [][]byte, pin *bridge.AuthPin) (*recordReceiptPending, error) {
	pushId, err := self.writer.drawId()
	if err != nil {
		return nil, err
	}
	depositId, err := self.writer.drawId()
	if err != nil {
		return nil, err
	}
	document := &recordReceiptDocument{
		Version:    recordReceiptVersion,
		LogId:      sealed.LogId,
		Seq:        sealed.Seq,
		Leaf:       bytes.Clone(sealed.Leaf[:]),
		PushId:     pushId,
		DepositId:  depositId,
		PinVersion: pin.GetVersion(),
		PinChain:   bytes.Clone(pin.GetChain()),
		Purpose:    uint32(purpose),
	}
	for _, objectId := range objectIds {
		document.ObjectIds = append(document.ObjectIds, bytes.Clone(objectId))
	}
	return &recordReceiptPending{document: document, sealed: sealed}, nil
}

// Writes a receipt's file, durably.
func (self *RecordReceipts) writeDocument(document *recordReceiptDocument) error {
	content, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("record receipt: %w", err)
	}
	if err := self.writer.chain.writeFile(recordReceiptName(document.LogId, document.Seq), content); err != nil {
		return fmt.Errorf("record receipt: %w", err)
	}
	return nil
}

// Seals one receipt of objects as this sidecar's next entry in the log and writes its file with fresh ids, before it
// is sent. Refused with nothing sealed when this sidecar may not deposit there or no pin is known. A file that fails
// to write leaves the entry journaled with none, which the next load takes up.
func (self *RecordReceipts) seal(receiptLog *recordReceiptLog, request *RecordReceiptRequest, objects []recordReceiptObject) (*recordReceiptPending, error) {
	auth := self.writer.auth()
	if !auth.Deposits(receiptLog.logId, self.writer.sidecarId) {
		return nil, fmt.Errorf("%w: %s", ErrRecordReceiptNotDepositor, receiptLog.logId)
	}
	pin := auth.Pin()
	if pin == nil {
		return nil, fmt.Errorf("%w: no auth pin to declare", ErrRecordReceiptRefused)
	}
	body := &protocol.ReadBody{Purpose: uint32(request.Purpose)}
	for _, object := range objects {
		body.ObjectIds = append(body.ObjectIds, []byte(object.id))
	}
	if err := RecordBodyValidate(RecordKindRead, body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordReceiptInvalid, err)
	}
	tainted := false
	switch {
	case request.RunId != nil:
		tainted = self.writer.runs.RunTainted(*request.RunId)
	case !request.NoSession:
		tainted = true
	}
	env := &RecordSealEnv{Chain: self.writer.chain, Sign: self.writer.sign, Random: self.writer.random}
	sealed, err := RecordSeal(env, &RecordSealArgs{
		LogId:         receiptLog.logId,
		Kind:          RecordKindRead,
		Source:        RecordSourceObserved,
		AgentSource:   RecordAgentSourceNone,
		TimeMillis:    self.writer.clock.Now().UnixMilli(),
		Tainted:       tainted,
		PolicyVersion: pin.GetVersion(),
		Body:          body,
	})
	if err != nil {
		return nil, err
	}
	pending, err := self.pendingOf(sealed, request.Purpose, body.GetObjectIds(), pin)
	if err == nil {
		err = self.writeDocument(pending.document)
	}
	if err != nil {
		sealed.Clear()
		receiptLog.unload()
		return nil, err
	}
	receiptLog.seqPendings[sealed.Seq] = pending
	return pending, nil
}

// Sends one pending receipt as its file names it, between its barriers. On evs's commit its file is marked; a
// refusal that spends the push id draws new ids for the next send; anything else leaves it to go again as it is. Each
// failure to land refuses the read.
func (self *RecordReceipts) send(ctx context.Context, receiptLog *recordReceiptLog, pending *recordReceiptPending) error {
	deposit, err := pending.deposit(self.writer.sidecarId)
	if err != nil {
		return err
	}
	// the batch holds the entry's key and salt until the binding seals it
	defer clear(deposit.Batch)
	streams := self.writer.boundStreams()
	testHookBarrier("record.receipt.deposit.before", receiptLog.hookKey)
	_, err = streams.Deposit(ctx, receiptLog.logId, deposit)
	testHookBarrier("record.receipt.deposit.after", receiptLog.hookKey)
	if err != nil {
		if code, refusal := RecordStreamRefusalCode(err); refusal && !EvsRefusalRefusesNothing(code) {
			self.redraw(pending)
		}
		return fmt.Errorf("%w: seq %d in log %s: %w", ErrRecordReceiptRefused, pending.document.Seq, receiptLog.logId, err)
	}
	self.committed(receiptLog, pending)
	return nil
}

// After a refusal that spent the push id: a new push id and deposit id and the pin now, written before the next send,
// for the same signed entry (§16.8). A write that fails keeps the spent ids, which evs refuses again, and that refusal
// draws again.
func (self *RecordReceipts) redraw(pending *recordReceiptPending) {
	pin := self.writer.auth().Pin()
	if pin == nil {
		pin = &bridge.AuthPin{Version: pending.document.PinVersion, Chain: pending.document.PinChain}
	}
	redrawn, err := self.pendingOf(pending.sealed, RecordReadPurpose(pending.document.Purpose), pending.document.ObjectIds, pin)
	if err == nil {
		err = self.writeDocument(redrawn.document)
	}
	if err != nil {
		self.writer.log.Warningf("[record]a refused receipt keeps its spent ids: %s", err)
		return
	}
	pending.document = redrawn.document
}

// evs committed the receipt: its objects count as receipted, its file is marked with the day, then its journal record
// is acknowledged. The read may go on either way, since evs holds the receipt. A mark that fails leaves the receipt
// pending on disk and here, so its next send, in this life or the next, answers this commit again and marks it; an
// acknowledgment that fails is taken up by the next load, which finds the file marked.
func (self *RecordReceipts) committed(receiptLog *recordReceiptLog, pending *recordReceiptPending) {
	for _, object := range pending.document.objects() {
		receiptLog.receipted[object] = true
	}
	marked := *pending.document
	marked.CommittedDay = receiptLog.day
	if err := self.writeDocument(&marked); err != nil {
		self.writer.log.Warningf("[record]a committed receipt stays pending until it is sent again: %s", err)
		return
	}
	delete(receiptLog.seqPendings, marked.Seq)
	pending.sealed.Clear()
	if err := self.writer.chain.Acknowledge(receiptLog.logId, []uint64{marked.Seq}); err != nil {
		self.writer.log.Warningf("[record]a committed receipt's journal record stays until the next load: %s", err)
	}
}
