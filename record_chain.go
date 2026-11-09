// RECORD.md section 5.3's chain and journal for this sidecar's own entries, on every leg. Per (log_id,
// writer_sidecar_id) seq runs from 1 with no gap, and each prev_sha256 is the leaf of the entry before, 32 zero bytes
// at seq 1. One fsynced journal record holds each signed entry with its head {seq, leaf} before the entry can leave
// the daemon, so the two move together, and the head file is only a compaction of the journal:
//
//	<log_id>                  the head {seq, leaf}, kept once the journal records holding it are acknowledged
//	journal/<log_id>/<seq>    one signed entry, its key and salt, and its head, until its push commits
//
// in the record component's sealed directory, <state>/net/<network_id>/record/ (§5.9). Ids are 32 lowercase hex
// characters and seq 20 decimal digits, so a listing sorts by seq. A crash before a record commits leaves nothing any
// reader saw, and the next entry takes that seq again; a crash after it leaves an entry that goes out with exactly
// its journaled bytes; so a writer's crash burns no seq, reuses none and raises no alarm. A file that does not decode
// is an error, never a fresh chain, since a fresh chain would sign seqs readers already pinned (I-16).
//
// The fsync of a journal record is the linearization point, record.chain.fsync, with .before and .after around it,
// keyed by the log. One log's appends run one at a time through it, since each chains on the one before, and a
// schedule holding one there stalls only that log's next append and adoption: Head, Pending and Acknowledge go on, and
// different logs' appends run side by side. Writes of a head file pass record.chain.head the same way.
//
// One chain store owns its directory: two on one directory would hand out the same seqs, so the record component makes
// one, and §5.8's lock keeps one process to an instance.
//
// On a restart the writer replays Pending, re-sending each entry whose push outcome it does not know, and a direct
// writer then takes the higher of its head here and its stream's newest entry of this chain (AdoptStream). A
// depositor reads no log, so a device restored from an old backup forks its chain, and readers alarm on the fork
// (RECORD.md section 5.3's restart row).
//
// Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/protocol/bridge"
)

// The chain files' format values. The byte bound is far above any real file, a blob's 8 MiB body in base64 among
// them, so it only stops a decoder from reading a garbage file whole.
const (
	recordChainFileVersion   = 1
	recordJournalDirectory   = "journal"
	recordChainSeqDigitCount = 20
	recordChainMaxByteCount  = 32 * 1024 * 1024
)

var (
	// A chain file that does not decode, or holds a chain no writer could have made: never read as a fresh chain.
	ErrRecordChainCorrupt = errors.New("record chain corrupt")
	// A head another copy of this writer signed at a seq this chain also holds, with another leaf: a fork, which
	// readers alarm on (RECORD.md section 5.5's chain step). The head here stands.
	ErrRecordChainForked = errors.New("record chain forked")
)

// A writer's chain head in one log: its newest seq and that entry's leaf. Seq 0 is a chain with no entry, whose next
// entry is seq 1 with prev_sha256 32 zero bytes, which the zero Leaf is.
type RecordChainHead struct {
	Seq  uint64
	Leaf [sha256.Size]byte
}

// The record component's chains, one a log, for one writer: this sidecar. The only one on its directory.
type RecordChainStore struct {
	store           SidecarStore
	writerSidecarId Id

	stateLock sync.Mutex
	logChains map[Id]*recordChain
}

// One log's chain, under four locks taken in this order. appendLock serializes appends and adoptions, from an append's
// take through its fsync, so a barrier held there stalls only what must follow it. headLock serializes writes of the
// head file, so it only rises. loadLock serializes the one load. Each is held across the store's I/O and never while
// waiting on anything else, and loadLock is released before headLock is taken. stateLock guards the fields below it,
// never across I/O or a barrier.
type recordChain struct {
	logId   Id
	hookKey string

	appendLock sync.Mutex
	headLock   sync.Mutex
	loadLock   sync.Mutex

	stateLock sync.Mutex
	loaded    bool
	head      RecordChainHead
	// the head file's own seq, which a compaction or an adoption raises
	headFileSeq uint64
	// journal records not yet acknowledged: seq to leaf
	pendingSeqLeafs map[uint64][sha256.Size]byte
}

// The head file's document.
type recordChainHeadDocument struct {
	Version         int    `json:"version"`
	LogId           Id     `json:"log_id"`
	WriterSidecarId Id     `json:"writer_sidecar_id"`
	Seq             uint64 `json:"seq"`
	Leaf            []byte `json:"leaf"`
}

// One journal record's document: a signed entry with its head, and its key and salt, which the store seals at rest.
type recordJournalDocument struct {
	Version         int    `json:"version"`
	LogId           Id     `json:"log_id"`
	WriterSidecarId Id     `json:"writer_sidecar_id"`
	Seq             uint64 `json:"seq"`
	Leaf            []byte `json:"leaf"`
	EntryId         Id     `json:"entry_id"`
	Signed          []byte `json:"signed"`
	SealedBody      []byte `json:"sealed_body"`
	Key             []byte `json:"key"`
	Salt            []byte `json:"salt"`
	// the writer's id of a spooled capture this entry seals (RecordSealArgs.CaptureId), when it has one
	CaptureId []byte `json:"capture_id,omitempty"`
}

// The chains of writerSidecarId, this sidecar, in store, the record component's sealed directory.
func NewRecordChainStore(store SidecarStore, writerSidecarId Id) *RecordChainStore {
	return &RecordChainStore{
		store:           store,
		writerSidecarId: writerSidecarId,
		logChains:       map[Id]*recordChain{},
	}
}

// The writer whose chains these are.
func (self *RecordChainStore) WriterSidecarId() Id {
	return self.writerSidecarId
}

// An id as the chain files name it: 32 lowercase hex characters.
func recordChainIdText(id Id) string {
	return hex.EncodeToString(id[:])
}

// The head file of a log.
func recordChainHeadName(logId Id) string {
	return recordChainIdText(logId)
}

// The journal record of a log's seq.
func recordJournalName(logId Id, seq uint64) string {
	return fmt.Sprintf("%s/%s/%0*d", recordJournalDirectory, recordChainIdText(logId), recordChainSeqDigitCount, seq)
}

// The log's chain, made on first use. Takes the state lock alone, and no I/O.
func (self *RecordChainStore) chain(logId Id) *recordChain {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	chain, ok := self.logChains[logId]
	if !ok {
		chain = &recordChain{logId: logId, hookKey: recordChainIdText(logId)}
		self.logChains[logId] = chain
	}
	return chain
}

// The whole file at name, nil with no error when there is none.
func (self *RecordChainStore) readFile(name string) ([]byte, error) {
	reader, err := self.store.Open(name)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, recordChainMaxByteCount+1))
	if err != nil {
		return nil, err
	}
	if recordChainMaxByteCount < len(content) {
		return nil, fmt.Errorf("%w: %s is past its bound", ErrRecordChainCorrupt, name)
	}
	return content, nil
}

// Replaces name with content, durably: when this returns nil, a power cut keeps it.
func (self *RecordChainStore) writeFile(name string, content []byte) error {
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	return writer.Commit()
}

// Decodes a chain file exactly, refusing a field it does not name.
func recordChainDecode(content []byte, document any) error {
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(document); err != nil {
		return err
	}
	if decoder.More() {
		return errors.New("trailing data")
	}
	return nil
}

// A journal record's document, checked against itself: its log and writer this chain's, its Signed a header of that
// writer and log at its seq, and its leaf that header's. A record that is not is corrupt.
func (self *RecordChainStore) decodeJournal(logId Id, seq uint64, content []byte) (*recordJournalDocument, error) {
	document := &recordJournalDocument{}
	if err := recordChainDecode(content, document); err != nil {
		return nil, fmt.Errorf("%w: journal record %d: %v", ErrRecordChainCorrupt, seq, err)
	}
	if document.Version != recordChainFileVersion || document.LogId != logId || document.WriterSidecarId != self.writerSidecarId ||
		document.Seq != seq || len(document.Key) != RecordKeyByteCount || len(document.Salt) != RecordSaltByteCount {
		return nil, fmt.Errorf("%w: journal record %d is not this chain's", ErrRecordChainCorrupt, seq)
	}
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(document.Signed, signed); err != nil {
		return nil, fmt.Errorf("%w: journal record %d: %v", ErrRecordChainCorrupt, seq, err)
	}
	header, err := ParseStoredRecordHeader(signed.GetBody())
	if err != nil {
		return nil, fmt.Errorf("%w: journal record %d: %v", ErrRecordChainCorrupt, seq, err)
	}
	leaf := header.LeafHash()
	if !bytes.Equal(document.Leaf, leaf[:]) || header.Header.GetSeq() != seq ||
		!bytes.Equal(header.Header.GetLogId(), logId[:]) || !bytes.Equal(header.Header.GetEntryId(), document.EntryId[:]) ||
		!bytes.Equal(header.Header.GetWriterSidecarId(), self.writerSidecarId[:]) {
		return nil, fmt.Errorf("%w: journal record %d does not hold its own header", ErrRecordChainCorrupt, seq)
	}
	return document, nil
}

// The prev_sha256 of a journal record's header.
func recordJournalPrev(document *recordJournalDocument) ([sha256.Size]byte, error) {
	signed := &bridge.Signed{}
	if err := proto.Unmarshal(document.Signed, signed); err != nil {
		return [sha256.Size]byte{}, err
	}
	header, err := ParseStoredRecordHeader(signed.GetBody())
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return [sha256.Size]byte(header.Header.GetPrevSha256()), nil
}

// The seqs of a log's journal records, ascending.
func (self *RecordChainStore) journalSeqs(logId Id) ([]uint64, error) {
	prefix := recordJournalDirectory + "/" + recordChainIdText(logId) + "/"
	entries, err := self.store.List(prefix)
	if err != nil {
		return nil, err
	}
	seqs := []uint64{}
	for _, entry := range entries {
		text := strings.TrimPrefix(entry.Name, prefix)
		seq, err := strconv.ParseUint(text, 10, 64)
		if err != nil || len(text) != recordChainSeqDigitCount || seq == 0 {
			return nil, fmt.Errorf("%w: a journal file named %q", ErrRecordChainCorrupt, entry.Name)
		}
		seqs = append(seqs, seq)
	}
	slices.Sort(seqs)
	return seqs, nil
}

// What a log's files hold: its head, the higher of the head file's and the journal's newest record; the head file's
// seq; and the journal's records not yet acknowledged.
type recordChainFiles struct {
	head            RecordChainHead
	headFileSeq     uint64
	pendingSeqLeafs map[uint64][sha256.Size]byte
}

// Loads the log's chain from its files, once, before any step that writes them, so nothing writes them while they
// are read.
func (self *RecordChainStore) ensureLoaded(chain *recordChain) error {
	loaded := func() bool {
		chain.stateLock.Lock()
		defer chain.stateLock.Unlock()
		return chain.loaded
	}
	if loaded() {
		return nil
	}
	chain.loadLock.Lock()
	defer chain.loadLock.Unlock()
	if loaded() {
		return nil
	}
	files, err := self.readChain(chain.logId)
	if err != nil {
		return err
	}
	chain.stateLock.Lock()
	defer chain.stateLock.Unlock()
	chain.head = files.head
	chain.headFileSeq = files.headFileSeq
	chain.pendingSeqLeafs = files.pendingSeqLeafs
	chain.loaded = true
	return nil
}

// Reads a log's head file and journal: two records at adjacent seqs must chain, as must the record just above the
// head file on it, and a record at the head file's seq must hold its leaf.
func (self *RecordChainStore) readChain(logId Id) (*recordChainFiles, error) {
	head := RecordChainHead{}
	content, err := self.readFile(recordChainHeadName(logId))
	if err != nil {
		return nil, err
	}
	if content != nil {
		document := &recordChainHeadDocument{}
		if err := recordChainDecode(content, document); err != nil {
			return nil, fmt.Errorf("%w: head: %v", ErrRecordChainCorrupt, err)
		}
		if document.Version != recordChainFileVersion || document.LogId != logId ||
			document.WriterSidecarId != self.writerSidecarId || document.Seq == 0 || len(document.Leaf) != sha256.Size {
			return nil, fmt.Errorf("%w: the head is not this chain's", ErrRecordChainCorrupt)
		}
		head = RecordChainHead{Seq: document.Seq, Leaf: [sha256.Size]byte(document.Leaf)}
	}
	headFile := head

	seqs, err := self.journalSeqs(logId)
	if err != nil {
		return nil, err
	}
	pendingSeqLeafs := map[uint64][sha256.Size]byte{}
	var previous *recordJournalDocument
	for _, seq := range seqs {
		content, err := self.readFile(recordJournalName(logId, seq))
		if err != nil {
			return nil, err
		}
		if content == nil {
			return nil, fmt.Errorf("%w: journal record %d went while it was read", ErrRecordChainCorrupt, seq)
		}
		document, err := self.decodeJournal(logId, seq, content)
		if err != nil {
			return nil, err
		}
		leaf := [sha256.Size]byte(document.Leaf)
		// a record chains on the record or head file at the seq below it, whichever holds that seq
		var below []byte
		switch {
		case previous != nil && previous.Seq+1 == seq:
			below = previous.Leaf
		case 0 < headFile.Seq && headFile.Seq+1 == seq:
			below = headFile.Leaf[:]
		}
		if below != nil {
			prev, err := recordJournalPrev(document)
			if err != nil || !bytes.Equal(prev[:], below) {
				return nil, fmt.Errorf("%w: journal record %d does not chain on seq %d", ErrRecordChainCorrupt, seq, seq-1)
			}
		}
		if seq == head.Seq && leaf != head.Leaf {
			return nil, fmt.Errorf("%w: journal record %d is not the head's entry", ErrRecordChainCorrupt, seq)
		}
		if head.Seq < seq {
			head = RecordChainHead{Seq: seq, Leaf: leaf}
		}
		pendingSeqLeafs[seq] = leaf
		previous = document
		clear(document.Key)
		clear(document.Salt)
	}
	return &recordChainFiles{head: head, headFileSeq: headFile.Seq, pendingSeqLeafs: pendingSeqLeafs}, nil
}

// The log's chain head: seq 0 for a log this writer has never written.
func (self *RecordChainStore) Head(logId Id) (RecordChainHead, error) {
	chain := self.chain(logId)
	if err := self.ensureLoaded(chain); err != nil {
		return RecordChainHead{}, err
	}
	chain.stateLock.Lock()
	defer chain.stateLock.Unlock()
	return chain.head, nil
}

// Takes the log's next (seq, prev_sha256), hands them to build, which signs the entry, and journals what it returns
// with one fsync before returning it. A build or journal failure leaves the head where it was, so the next append
// takes the same seq; the fsync's success is the entry's linearization point.
func (self *RecordChainStore) append(logId Id, build func(seq uint64, prev [sha256.Size]byte) (*RecordSealedEntry, error)) (*RecordSealedEntry, error) {
	chain := self.chain(logId)
	chain.appendLock.Lock()
	defer chain.appendLock.Unlock()
	if err := self.ensureLoaded(chain); err != nil {
		return nil, err
	}
	// only an append or an adoption moves the head, and either holds appendLock
	head := func() RecordChainHead {
		chain.stateLock.Lock()
		defer chain.stateLock.Unlock()
		return chain.head
	}()
	if head.Seq == ^uint64(0) {
		return nil, fmt.Errorf("%w: the chain has no seq left", ErrRecordSealInvalid)
	}
	seq := head.Seq + 1
	entry, err := build(seq, head.Leaf)
	if err != nil {
		return nil, err
	}
	if entry.Seq != seq || entry.LogId != logId {
		return nil, fmt.Errorf("%w: built seq %d of another log, for seq %d", ErrRecordSealInvalid, entry.Seq, seq)
	}
	content, err := json.Marshal(&recordJournalDocument{
		Version:         recordChainFileVersion,
		LogId:           logId,
		WriterSidecarId: self.writerSidecarId,
		Seq:             seq,
		Leaf:            entry.Leaf[:],
		EntryId:         entry.EntryId,
		Signed:          entry.Signed,
		SealedBody:      entry.SealedBody,
		Key:             entry.Key,
		Salt:            entry.Salt,
		CaptureId:       entry.CaptureId,
	})
	if err != nil {
		return nil, fmt.Errorf("record chain: %w", err)
	}
	defer clear(content)
	testHookBarrier("record.chain.fsync.before", chain.hookKey)
	if err := self.writeFile(recordJournalName(logId, seq), content); err != nil {
		return nil, fmt.Errorf("record chain: journal: %w", err)
	}
	testHookBarrier("record.chain.fsync.after", chain.hookKey)
	func() {
		chain.stateLock.Lock()
		defer chain.stateLock.Unlock()
		chain.head = RecordChainHead{Seq: seq, Leaf: entry.Leaf}
		chain.pendingSeqLeafs[seq] = entry.Leaf
	}()
	return entry, nil
}

// Every journaled entry of logId not yet acknowledged, in seq order, with exactly the bytes it was signed and sealed
// with: what a restarted writer re-sends when it does not know a push's outcome (D-MCP-10). Each holds its key and
// salt, which the caller clears once it is done with them.
func (self *RecordChainStore) Pending(logId Id) ([]*RecordSealedEntry, error) {
	chain := self.chain(logId)
	if err := self.ensureLoaded(chain); err != nil {
		return nil, err
	}
	pending := func(seq uint64) bool {
		chain.stateLock.Lock()
		defer chain.stateLock.Unlock()
		_, ok := chain.pendingSeqLeafs[seq]
		return ok
	}
	seqs := func() []uint64 {
		chain.stateLock.Lock()
		defer chain.stateLock.Unlock()
		seqs := make([]uint64, 0, len(chain.pendingSeqLeafs))
		for seq := range chain.pendingSeqLeafs {
			seqs = append(seqs, seq)
		}
		return seqs
	}()
	slices.Sort(seqs)
	entries := make([]*RecordSealedEntry, 0, len(seqs))
	for _, seq := range seqs {
		content, err := self.readFile(recordJournalName(logId, seq))
		if err != nil {
			return nil, err
		}
		if content == nil {
			// an acknowledgment takes a seq out of the pending set before it removes its record
			if !pending(seq) {
				continue
			}
			return nil, fmt.Errorf("%w: journal record %d is gone", ErrRecordChainCorrupt, seq)
		}
		document, err := self.decodeJournal(logId, seq, content)
		clear(content)
		if err != nil {
			return nil, err
		}
		// the record's keys come back out of local state: the writer's unwrap of them
		testHookSecret("record_entry_key", document.Key)
		testHookSecret("record_entry_salt", document.Salt)
		entries = append(entries, &RecordSealedEntry{
			LogId:      logId,
			EntryId:    document.EntryId,
			Seq:        seq,
			Leaf:       [sha256.Size]byte(document.Leaf),
			Signed:     document.Signed,
			SealedBody: document.SealedBody,
			Key:        document.Key,
			Salt:       document.Salt,
			CaptureId:  document.CaptureId,
		})
	}
	return entries, nil
}

// The logs with a journal record not yet acknowledged, whose entries a restarted writer replays.
func (self *RecordChainStore) PendingLogIds() ([]Id, error) {
	entries, err := self.store.List(recordJournalDirectory + "/")
	if err != nil {
		return nil, err
	}
	logIds := []Id{}
	for _, entry := range entries {
		parts := strings.Split(entry.Name, "/")
		if len(parts) != 3 {
			return nil, fmt.Errorf("%w: a journal file named %q", ErrRecordChainCorrupt, entry.Name)
		}
		logIdBytes, err := hex.DecodeString(parts[1])
		if err != nil || len(logIdBytes) != len(Id{}) || parts[1] != strings.ToLower(parts[1]) {
			return nil, fmt.Errorf("%w: a journal directory named %q", ErrRecordChainCorrupt, parts[1])
		}
		logId := Id(logIdBytes)
		if !slices.Contains(logIds, logId) {
			logIds = append(logIds, logId)
		}
	}
	return logIds, nil
}

// Drops seqs' journal records once their entries are committed or found in a stream, keeping the head: when a
// dropped record holds a seq above the head file's, the head file takes it first, so the head survives the
// record. A seq the journal does not hold is skipped, so an acknowledgment may repeat.
func (self *RecordChainStore) Acknowledge(logId Id, seqs []uint64) error {
	chain := self.chain(logId)
	if err := self.ensureLoaded(chain); err != nil {
		return err
	}
	chain.headLock.Lock()
	defer chain.headLock.Unlock()
	held := []uint64{}
	var highest RecordChainHead
	var headFileSeq uint64
	func() {
		chain.stateLock.Lock()
		defer chain.stateLock.Unlock()
		for _, seq := range seqs {
			leaf, ok := chain.pendingSeqLeafs[seq]
			if ok && !slices.Contains(held, seq) {
				held = append(held, seq)
				if highest.Seq < seq {
					highest = RecordChainHead{Seq: seq, Leaf: leaf}
				}
			}
		}
		headFileSeq = chain.headFileSeq
	}()
	if len(held) == 0 {
		return nil
	}
	if headFileSeq < highest.Seq {
		if err := self.writeHeadWithLock(chain, highest); err != nil {
			return err
		}
	}
	// out of the pending set first, so a Pending racing the removal skips a record it finds gone; a removal that
	// fails leaves a record the next life replays, and an entry already committed is only found there again
	func() {
		chain.stateLock.Lock()
		defer chain.stateLock.Unlock()
		for _, seq := range held {
			delete(chain.pendingSeqLeafs, seq)
		}
	}()
	for _, seq := range held {
		if err := self.store.Remove(recordJournalName(logId, seq)); err != nil {
			return fmt.Errorf("record chain: %w", err)
		}
	}
	return nil
}

// Writes head as the log's head file, durably, under headLock, so the head file only rises.
func (self *RecordChainStore) writeHeadWithLock(chain *recordChain, head RecordChainHead) error {
	content, err := json.Marshal(&recordChainHeadDocument{
		Version:         recordChainFileVersion,
		LogId:           chain.logId,
		WriterSidecarId: self.writerSidecarId,
		Seq:             head.Seq,
		Leaf:            head.Leaf[:],
	})
	if err != nil {
		return fmt.Errorf("record chain: %w", err)
	}
	testHookBarrier("record.chain.head.before", chain.hookKey)
	if err := self.writeFile(recordChainHeadName(chain.logId), content); err != nil {
		return fmt.Errorf("record chain: head: %w", err)
	}
	testHookBarrier("record.chain.head.after", chain.hookKey)
	chain.stateLock.Lock()
	defer chain.stateLock.Unlock()
	chain.headFileSeq = max(chain.headFileSeq, head.Seq)
	return nil
}

// Raises the log's head to head when its seq is higher, durably, and answers whether it did: a restarted direct
// writer's newest entry in its own stream, so its next entry chains on what readers hold rather than on a head its
// local state lost. A head at a seq this chain holds with another leaf is ErrRecordChainForked, and the head here
// stands.
func (self *RecordChainStore) Adopt(logId Id, head RecordChainHead) (bool, error) {
	chain := self.chain(logId)
	chain.appendLock.Lock()
	defer chain.appendLock.Unlock()
	if err := self.ensureLoaded(chain); err != nil {
		return false, err
	}
	chain.headLock.Lock()
	defer chain.headLock.Unlock()
	raise, err := func() (bool, error) {
		chain.stateLock.Lock()
		defer chain.stateLock.Unlock()
		if head.Seq == chain.head.Seq && head.Leaf != chain.head.Leaf {
			return false, fmt.Errorf("%w: seq %d", ErrRecordChainForked, head.Seq)
		}
		if leaf, ok := chain.pendingSeqLeafs[head.Seq]; ok && leaf != head.Leaf {
			return false, fmt.Errorf("%w: seq %d", ErrRecordChainForked, head.Seq)
		}
		return chain.head.Seq < head.Seq, nil
	}()
	if err != nil || !raise {
		return false, err
	}
	if err := self.writeHeadWithLock(chain, head); err != nil {
		return false, err
	}
	chain.stateLock.Lock()
	defer chain.stateLock.Unlock()
	chain.head = head
	return true, nil
}

// Reads this writer's own stream of logId and adopts its newest entry of this chain (Adopt), answering whether the
// head rose. identityKey is this sidecar's Ed25519 public key, which every entry it adopts must verify under.
func (self *RecordChainStore) AdoptStream(ctx context.Context, streams RecordStreams, logId Id, identityKey []byte) (bool, error) {
	head, ok, err := RecordStreamChainHead(ctx, streams, logId, self.writerSidecarId, identityKey)
	if err != nil || !ok {
		return false, err
	}
	return self.Adopt(logId, *head)
}

// The newest entry of writerSidecarId's chain in its own stream of logId, read newest push first, doubling the
// window back until a push holds one: a writer pushes its chain in seq order, so the newest push holding any of it
// holds its head. Only an entry whose header verifies under identityKey, as writerSidecarId's in logId, counts, so a
// server cannot raise a writer's head by planting one. False when the stream holds none.
func RecordStreamChainHead(ctx context.Context, streams RecordStreams, logId Id, writerSidecarId Id, identityKey []byte) (*RecordChainHead, bool, error) {
	heads, err := streams.Streams(ctx, logId)
	if err != nil {
		return nil, false, err
	}
	var newest uint64
	for _, head := range heads {
		if head.SidecarId == writerSidecarId {
			newest = head.Version
		}
	}
	// versions above scannedAfter, up to newest, are read; one pushed since Streams answered waits for the next restart
	scannedAfter := newest
	window := uint64(1)
	var found *RecordChainHead
	for 0 < scannedAfter {
		after := uint64(0)
		if window < newest {
			after = newest - window
		}
		versions, err := streams.ReadStream(ctx, logId, writerSidecarId, after)
		if err != nil {
			return nil, false, err
		}
		for _, version := range versions {
			if version.Version <= after || scannedAfter < version.Version {
				continue
			}
			for _, streamEntry := range version.Entries {
				seq, leaf, ok := recordStreamEntryOf(streamEntry.Entry, logId, writerSidecarId, identityKey)
				if ok && (found == nil || found.Seq < seq) {
					found = &RecordChainHead{Seq: seq, Leaf: leaf}
				}
			}
		}
		if found != nil {
			return found, true, nil
		}
		scannedAfter = after
		window *= 2
	}
	return nil, false, nil
}

// The seq and leaf of a stream entry's header when it verifies as writerSidecarId's entry in logId under
// identityKey; false for anything else, such as another writer's entry an ingester keeps there.
func recordStreamEntryOf(entryBytes []byte, logId Id, writerSidecarId Id, identityKey []byte) (uint64, [sha256.Size]byte, bool) {
	entry := &protocol.RecordEntry{}
	if err := proto.Unmarshal(entryBytes, entry); err != nil || entry.GetHeader() == nil {
		return 0, [sha256.Size]byte{}, false
	}
	header, err := ParseStoredRecordHeader(entry.GetHeader().GetBody())
	if err != nil || !bytes.Equal(header.Header.GetLogId(), logId[:]) ||
		!bytes.Equal(header.Header.GetWriterSidecarId(), writerSidecarId[:]) ||
		!bytes.Equal(entry.GetHeader().GetSignerId(), writerSidecarId[:]) {
		return 0, [sha256.Size]byte{}, false
	}
	err = bridge.VerifySigned(entry.GetHeader(), RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, identityKey)
	if err != nil {
		return 0, [sha256.Size]byte{}, false
	}
	return header.Header.GetSeq(), header.LeafHash(), true
}
