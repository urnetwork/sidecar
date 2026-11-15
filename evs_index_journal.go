//go:build !ios_extension

// The journal (§11.11's index row, §11.14's companion row; FI-18; DESIGN-DETAILS 1.2.6's journal and 1.7's note for
// SEARCH-M10-14; SEARCH-M10-14): the entries a committer owes ur/index for the content it pushed to a git-mode ref or
// a record stream, from the moment its push commits until a companion push publishes them.
//
//	unit      {content ref_id, content version c, that push's signed time, state, documents}; a document is
//	          {doc_key, name, chunk, version v, put or remove}, a put with its row and key set as extraction gave them;
//	          a ref DELETE's unit holds one ref tombstone {ref_id, the version it committed at}
//	state     committed: c is a committed version this sidecar signed; sent: the unit is in a built companion push
//	          whose outcome is not known
//	writes    Committed appends a unit once the replica applies a version this sidecar signed above q_R (section
//	          8's settle, a stream append's committed outcome): its caller decides when, and nothing is journaled for
//	          a push that has not committed, so no unit names a version evs does not hold
//	leaves    published at its companion push's commit; superseded, covered or erased at a build; sent units return
//	          to committed when their push is refused or its life passes unsent
//	bound     past Search.JournalByteCount the oldest units lose their key sets and rows and keep their documents'
//	          keys and versions; a build extracts them again from the text, or drops the unit to be backfilled
//	epoch     each unit is stamped with the index epoch of ur/index the journal had seen when it was journaled, which
//	          is never above the epoch at its commit; a build whose erasure set's listed_since passes a unit's stamp
//	          strips it as the bound does, since the set may have dropped a complete erasure the unit's key sets
//	          still hold (§11.14's epoch row; the epoch guard's rebuildJournal)
//	search    the device's own searches read committed and sent units as a local overlay (searchJournalEntries,
//	          the local layer's seam); ApplyErase and ApplyCut remove a listed document's units
//
// One repo's units are files of the search journal directory of the network's store, sealed under file class search,
// one a unit, named by an ascending sequence, each written whole and rewritten whole at a change of state, so a unit
// is read by stream and the journal never whole (QD-641). A unit file is a JSON head and, after it, each put's entry
// in the index's slot entry codec (INDEX-FORMAT.md), which keeps its key set and row exact.
//
// Not here: a record stream's card markers and again units (DESIGN-DETAILS 15.2.9), which wait on SEARCH-M10-28's
// cards. Paths are this device's plaintext, sealed in the store, and go into no log or error (I-13). Safe for
// concurrent use.

package sidecar

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// The journal's directory in a network's store, beside the index cache's, and its unit files' format.
const (
	sidecarSearchJournalDir = "search-journal"
	indexJournalFormat      = 1
)

// A unit file that does not read: dropped, its push backfilled.
var errIndexJournalUndecodable = errors.New("index journal unit undecodable")

// A unit's state.
type indexJournalState string

const (
	indexJournalCommitted indexJournalState = "committed"
	indexJournalSent      indexJournalState = "sent"
)

// One document of a unit.
type indexJournalDocument struct {
	key   [indexIdByteCount]byte
	name  string
	chunk uint32
	// The path's entry version, or its removal's.
	version uint64
	remove  bool
	// A ref DELETE's ref tombstone: key is the ref_id.
	refTombstone bool
	// A put's key set and row as extraction gave them; nil once the bound stripped them.
	keys indexKeySet
	row  *indexRow
}

// One unit: what a committed content version owes the index.
type indexJournalUnit struct {
	seq          uint64
	refId        Id
	version      uint64
	signedTimeMs int64
	state        indexJournalState
	// The companion push a sent unit is in.
	pushId Id
	// The bound took its key sets.
	stripped bool
	// The index epoch the journal had seen when the unit was journaled: work begun there.
	epoch     uint64
	documents []*indexJournalDocument
}

// The head of a unit file.
type indexJournalUnitWire struct {
	Format       int                        `json:"format"`
	RefId        string                     `json:"ref_id"`
	Version      uint64                     `json:"version"`
	SignedTimeMs int64                      `json:"signed_time_ms"`
	State        string                     `json:"state"`
	PushId       string                     `json:"push_id,omitempty"`
	Stripped     bool                       `json:"stripped,omitempty"`
	Epoch        uint64                     `json:"epoch,omitempty"`
	Documents    []indexJournalDocumentWire `json:"documents"`
}

// A document in a unit file's head; a put's entry follows the head unless the unit is stripped.
type indexJournalDocumentWire struct {
	Key          string `json:"doc_key"`
	Name         string `json:"name"`
	Chunk        uint32 `json:"chunk,omitempty"`
	Version      uint64 `json:"version"`
	Remove       bool   `json:"remove,omitempty"`
	RefTombstone bool   `json:"ref_tombstone,omitempty"`
}

// One repo's journal. Construct with newIndexJournal.
type IndexJournal struct {
	store    SidecarStore
	repoId   Id
	settings *SidecarSearchSettings
	format   *IndexFormatSettings

	stateLock sync.Mutex
	nextSeq   uint64
	// The highest index epoch of ur/index a build has read, which a unit journaled now is stamped with.
	observedEpoch uint64
}

// The journal of repoId in a network's store, its units read back from earlier runs.
func newIndexJournal(store SidecarStore, repoId Id, settings *SidecarSearchSettings, format *IndexFormatSettings) (*IndexJournal, error) {
	if store == nil || settings == nil || format == nil || repoId == (Id{}) {
		return nil, fmt.Errorf("%w: a journal needs its store, repo and settings", ErrSearchCacheArgs)
	}
	directory, err := store.Directory(sidecarSearchJournalDir, SidecarSearchFileClass)
	if err != nil {
		return nil, err
	}
	journal := &IndexJournal{store: directory, repoId: repoId, settings: settings, format: format, nextSeq: 1}
	seqs, err := journal.seqs()
	if err != nil {
		return nil, err
	}
	if 0 < len(seqs) {
		journal.nextSeq = seqs[len(seqs)-1] + 1
		// the newest unit's stamp is the epoch the journal had seen last; with none readable, 0, which only strips more
		journal.observedEpoch = journal.newestEpoch(seqs[len(seqs)-1])
	}
	return journal, nil
}

// The epoch stamped on the unit of seq, 0 where it does not read.
func (self *IndexJournal) newestEpoch(seq uint64) uint64 {
	reader, err := self.store.Open(self.name(seq))
	if err != nil {
		return 0
	}
	file, err := io.ReadAll(reader)
	reader.Close()
	if err != nil {
		return 0
	}
	unit, err := self.decode(seq, file)
	if err != nil {
		return 0
	}
	return unit.epoch
}

// The repo's directory prefix of unit files.
func (self *IndexJournal) prefix() string {
	return hex.EncodeToString(self.repoId[:]) + "/"
}

// A unit's file name: its sequence, zero-padded so names sort as sequences do.
func (self *IndexJournal) name(seq uint64) string {
	return self.prefix() + fmt.Sprintf("%020d", seq)
}

// The units' sequences, ascending, and what they take in the store.
func (self *IndexJournal) seqs() ([]uint64, error) {
	entries, err := self.store.List(self.prefix())
	if err != nil {
		return nil, err
	}
	seqs := []uint64{}
	for _, entry := range entries {
		seq, err := strconv.ParseUint(strings.TrimPrefix(entry.Name, self.prefix()), 10, 64)
		if err == nil {
			seqs = append(seqs, seq)
		}
	}
	slices.Sort(seqs)
	return seqs, nil
}

// The bytes the journal's units take in the store.
func (self *IndexJournal) ByteCount() (int64, error) {
	entries, err := self.store.List(self.prefix())
	if err != nil {
		return 0, err
	}
	byteCount := int64(0)
	for _, entry := range entries {
		byteCount += entry.ByteCount
	}
	return byteCount, nil
}

// A unit's file.
func (self *IndexJournal) encode(unit *indexJournalUnit) ([]byte, error) {
	wire := indexJournalUnitWire{
		Format: indexJournalFormat, RefId: hex.EncodeToString(unit.refId[:]), Version: unit.version,
		SignedTimeMs: unit.signedTimeMs, State: string(unit.state), Stripped: unit.stripped, Epoch: unit.epoch,
		Documents: []indexJournalDocumentWire{},
	}
	if unit.pushId != (Id{}) {
		wire.PushId = hex.EncodeToString(unit.pushId[:])
	}
	tail := []byte{}
	for _, document := range unit.documents {
		wire.Documents = append(wire.Documents, indexJournalDocumentWire{
			Key: hex.EncodeToString(document.key[:]), Name: document.name, Chunk: document.chunk, Version: document.version,
			Remove: document.remove, RefTombstone: document.refTombstone,
		})
		if unit.stripped || document.remove || document.refTombstone {
			continue
		}
		entry := &indexEntry{kind: indexEntryFull, key: document.key, version: document.version, row: document.row, keys: document.keys}
		encoded, err := entry.appendEncoded(nil, true, self.format)
		if err != nil {
			return nil, err
		}
		tail = binary.BigEndian.AppendUint32(tail, uint32(len(encoded)))
		tail = append(tail, encoded...)
	}
	head, err := json.Marshal(wire)
	if err != nil {
		return nil, err
	}
	file := binary.BigEndian.AppendUint32(nil, uint32(len(head)))
	file = append(file, head...)
	return append(file, tail...), nil
}

// A unit file read back.
func (self *IndexJournal) decode(seq uint64, file []byte) (*indexJournalUnit, error) {
	if len(file) < 4 {
		return nil, errIndexJournalUndecodable
	}
	headLength := int(binary.BigEndian.Uint32(file))
	if len(file) < 4+headLength {
		return nil, errIndexJournalUndecodable
	}
	wire := indexJournalUnitWire{}
	if json.Unmarshal(file[4:4+headLength], &wire) != nil || wire.Format != indexJournalFormat {
		return nil, errIndexJournalUndecodable
	}
	refId, err := searchIdOfWire(wire.RefId)
	if err != nil {
		return nil, errIndexJournalUndecodable
	}
	unit := &indexJournalUnit{
		seq: seq, refId: refId, version: wire.Version, signedTimeMs: wire.SignedTimeMs,
		state: indexJournalState(wire.State), stripped: wire.Stripped, epoch: wire.Epoch,
	}
	if unit.state != indexJournalCommitted && unit.state != indexJournalSent {
		return nil, errIndexJournalUndecodable
	}
	if wire.PushId != "" {
		if unit.pushId, err = searchIdOfWire(wire.PushId); err != nil {
			return nil, errIndexJournalUndecodable
		}
	}
	tail := file[4+headLength:]
	for _, documentWire := range wire.Documents {
		key, err := hex.DecodeString(documentWire.Key)
		if err != nil || len(key) != indexIdByteCount {
			return nil, errIndexJournalUndecodable
		}
		document := &indexJournalDocument{
			key: [indexIdByteCount]byte(key), name: documentWire.Name, chunk: documentWire.Chunk, version: documentWire.Version,
			remove: documentWire.Remove, refTombstone: documentWire.RefTombstone,
		}
		if !unit.stripped && !document.remove && !document.refTombstone {
			if len(tail) < 4 || len(tail) < 4+int(binary.BigEndian.Uint32(tail)) {
				return nil, errIndexJournalUndecodable
			}
			length := int(binary.BigEndian.Uint32(tail))
			decoder := indexDecoder{src: tail[4 : 4+length]}
			entry := decoder.entry(true, self.format)
			if decoder.err != nil || entry.kind != indexEntryFull || entry.key != document.key || entry.version != document.version {
				return nil, errIndexJournalUndecodable
			}
			document.keys, document.row = entry.keys, entry.row
			tail = tail[4+length:]
		}
		unit.documents = append(unit.documents, document)
	}
	return unit, nil
}

// Writes a unit's file whole.
func (self *IndexJournal) write(unit *indexJournalUnit) error {
	file, err := self.encode(unit)
	if err != nil {
		return err
	}
	writer, err := self.store.Create(self.name(unit.seq))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(file); err != nil {
		return err
	}
	return writer.Commit()
}

// Appends a committed unit: a version of a content ref this sidecar signed that its replica applied above q_R. The
// bound then strips the oldest units' key sets.
func (self *IndexJournal) Committed(unit *indexJournalUnit) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	stored := *unit
	stored.seq = self.nextSeq
	stored.state = indexJournalCommitted
	stored.pushId = Id{}
	stored.epoch = self.observedEpoch
	if err := self.write(&stored); err != nil {
		return err
	}
	self.nextSeq += 1
	unit.seq = stored.seq
	return self.boundWithLock()
}

// Past Search.JournalByteCount, strips the oldest units' key sets and rows until the journal fits or none is left to
// strip.
func (self *IndexJournal) boundWithLock() error {
	byteCount, err := self.ByteCount()
	if err != nil || byteCount <= self.settings.JournalByteCount {
		return err
	}
	return self.eachWithLock(func(unit *indexJournalUnit) (bool, error) {
		if unit.stripped {
			return true, nil
		}
		unit.stripped = true
		for _, document := range unit.documents {
			document.keys, document.row = nil, nil
		}
		if err := self.write(unit); err != nil {
			return false, err
		}
		byteCount, err := self.ByteCount()
		return self.settings.JournalByteCount < byteCount, err
	})
}

// Takes epoch, the index epoch a build read at ur/index's head, as seen: units journaled from now are stamped with it.
func (self *IndexJournal) observe(epoch uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.observedEpoch = max(self.observedEpoch, epoch)
	return nil
}

// Strips the key sets and rows of every unit stamped below listedSince, as the bound does, so a build extracts each
// again from the text or drops it to backfill; answers how many it stripped.
func (self *IndexJournal) stripBelow(listedSince uint64) (int, error) {
	if listedSince == 0 {
		return 0, nil
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	stripped := 0
	err := self.eachWithLock(func(unit *indexJournalUnit) (bool, error) {
		if unit.stripped || listedSince <= unit.epoch {
			return true, nil
		}
		unit.stripped = true
		for _, document := range unit.documents {
			document.keys, document.row = nil, nil
		}
		stripped += 1
		return true, self.write(unit)
	})
	return stripped, err
}

// Visits every unit in sequence order, one read at a time, until visit answers false. A unit file that does not read
// is dropped: its push reads unindexed and a backfill covers it.
func (self *IndexJournal) each(visit func(unit *indexJournalUnit) (bool, error)) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.eachWithLock(visit)
}

// each, the lock held.
func (self *IndexJournal) eachWithLock(visit func(unit *indexJournalUnit) (bool, error)) error {
	seqs, err := self.seqs()
	if err != nil {
		return err
	}
	for _, seq := range seqs {
		reader, err := self.store.Open(self.name(seq))
		if errors.Is(err, ErrSidecarStoreAbsent) {
			continue
		}
		if err != nil {
			return err
		}
		file, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return err
		}
		unit, err := self.decode(seq, file)
		if err != nil {
			if err := self.store.Remove(self.name(seq)); err != nil {
				return err
			}
			continue
		}
		more, err := visit(unit)
		if err != nil || !more {
			return err
		}
	}
	return nil
}

// The units, copies, in sequence order.
func (self *IndexJournal) units() ([]*indexJournalUnit, error) {
	units := []*indexJournalUnit{}
	err := self.each(func(unit *indexJournalUnit) (bool, error) {
		units = append(units, unit)
		return true, nil
	})
	return units, err
}

// Sets the units of seqs to state, sent ones naming pushId.
func (self *IndexJournal) setState(seqs []uint64, state indexJournalState, pushId Id) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.eachWithLock(func(unit *indexJournalUnit) (bool, error) {
		if !slices.Contains(seqs, unit.seq) {
			return true, nil
		}
		unit.state = state
		unit.pushId = Id{}
		if state == indexJournalSent {
			unit.pushId = pushId
		}
		return true, self.write(unit)
	})
}

// Removes the units of seqs: published, or dropped at a build.
func (self *IndexJournal) remove(seqs []uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, seq := range seqs {
		if err := self.store.Remove(self.name(seq)); err != nil && !errors.Is(err, ErrSidecarStoreAbsent) {
			return err
		}
	}
	return nil
}

// Removes from every unit the documents listed reports listed, dropping a unit left with none: an ERASE's keys, or a
// CUT's documents at or below their versions (CORE-M10-04's ApplyErase and ApplyCut call these).
func (self *IndexJournal) removeListed(listed func(document *indexJournalDocument) bool) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.eachWithLock(func(unit *indexJournalUnit) (bool, error) {
		kept := slices.DeleteFunc(slices.Clone(unit.documents), listed)
		if len(kept) == len(unit.documents) {
			return true, nil
		}
		if len(kept) == 0 {
			return true, self.store.Remove(self.name(unit.seq))
		}
		unit.documents = kept
		return true, self.write(unit)
	})
}

// An ERASE: every unit document of keys goes, at any version.
func (self *IndexJournal) ApplyErase(keys [][indexIdByteCount]byte) error {
	return self.removeListed(func(document *indexJournalDocument) bool {
		return slices.Contains(keys, document.key)
	})
}

// A CUT: every unit document the erasure set lists at or above its version goes; erased is the set's test, the view's.
func (self *IndexJournal) ApplyCut(erased func(key [indexIdByteCount]byte, version uint64) bool) error {
	return self.removeListed(func(document *indexJournalDocument) bool {
		return !document.refTombstone && erased(document.key, document.version)
	})
}

// The local layer's seam (searchLocalJournal): each committed or sent unit's documents as the companion push will
// carry them, full entries with their key sets and rows, tombstones, and ref tombstones; a stripped unit's puts are
// left out, since they hold nothing to match.
func (self *IndexJournal) searchJournalEntries(visit func(entry *indexEntry) error) error {
	return self.each(func(unit *indexJournalUnit) (bool, error) {
		timeSeconds := indexEntrySeconds(unit.signedTimeMs)
		for _, document := range unit.documents {
			entry := &indexEntry{key: document.key, version: document.version, timeSeconds: timeSeconds}
			switch {
			case document.refTombstone:
				entry.kind = indexEntryRefTombstone
			case document.remove:
				entry.kind = indexEntryTombstone
			case unit.stripped || document.keys == nil:
				continue
			default:
				entry.kind, entry.keys, entry.row = indexEntryFull, document.keys, document.row
			}
			if err := visit(entry); err != nil {
				return false, err
			}
		}
		return true, nil
	})
}
