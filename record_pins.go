// RECORD.md section 5.5's chain step and I-16's pins, on every leg: per log, each writer's chain as this reader has
// read it, across every stream of the log, since two ingesters can split one writer's entries, and the pins it keeps
// in the record component's sealed directory, so a stream wound back or a chain rewritten after a restart shows:
//
//	read/<log_id>   each stream's version read through, and each writer's contiguous head {seq, leaf}
//
// A writer's chain runs seq from 1, prev_sha256 32 zero bytes at seq 1 and the leaf before after it. A leaf already
// held is a copy, shown once with every copy's place kept. A seq held with another leaf, or an entry whose prev is not
// the held leaf at seq - 1, is a fork: both are kept, the later shown forked, and chain_fork raised. A seq past the
// contiguous head + 1 is a gap: kept, and chain_gap raised at once for a writer with no deposit right on the log, whose
// stream lands in seq order, and past ChainGapTimeout for one that deposits, since one ingester's push can land before
// another's. After a sync, a head below its pin, or a pinned seq holding another leaf, alarms; a stream's version
// below its pin is a stream wound back, chain_fork. Expiry by BASE (section 5.5's expired row) is not told from a gap
// here: BASE is not yet on RecordStreams, so a chain cut by expiry alarms too.
//
// Not safe for concurrent use: the reader holds each log's sync lock around it.

package sidecar

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// The pin file's format values.
const (
	recordPinDirectory = "read"
	recordPinVersion   = 1
)

// One writer's chain in one log, as read.
type recordReadChain struct {
	// the first leaf seen at each seq
	seqLeafs map[uint64][sha256.Size]byte
	// leaves of entries shown forked, whose successors are forked too
	forkedLeafs map[[sha256.Size]byte]bool
	// the highest seq every seq below which, from 1, is held unforked
	head uint64
	// when the current gap was first seen, Unix milliseconds, 0 for none
	gapMillis  int64
	gapAlarmed bool
}

// An empty chain, its head at 0.
func newRecordReadChain() *recordReadChain {
	return &recordReadChain{seqLeafs: map[uint64][sha256.Size]byte{}, forkedLeafs: map[[sha256.Size]byte]bool{}}
}

// What adding an entry to its writer's chain found.
type recordChainVerdict struct {
	forked bool
	// the entry leaves a gap below it
	gap bool
}

// Adds an entry at seq with prev and leaf, which is not a copy of one held.
func (self *recordReadChain) add(seq uint64, prev [sha256.Size]byte, leaf [sha256.Size]byte) *recordChainVerdict {
	verdict := &recordChainVerdict{}
	if held, ok := self.seqLeafs[seq]; ok && held != leaf {
		verdict.forked = true
	}
	if seq == 1 && prev != ([sha256.Size]byte{}) {
		verdict.forked = true
	}
	if below, ok := self.seqLeafs[seq-1]; ok && 1 < seq && below != prev {
		verdict.forked = true
	}
	if self.forkedLeafs[prev] {
		verdict.forked = true
	}
	if verdict.forked {
		self.forkedLeafs[leaf] = true
		return verdict
	}
	self.seqLeafs[seq] = leaf
	for {
		if _, ok := self.seqLeafs[self.head+1]; !ok {
			break
		}
		self.head += 1
	}
	verdict.gap = self.head < self.highest()
	return verdict
}

// The highest seq held.
func (self *recordReadChain) highest() uint64 {
	var highest uint64
	for seq := range self.seqLeafs {
		highest = max(highest, seq)
	}
	return highest
}

// The pin file's document.
type recordPinDocument struct {
	Version int                    `json:"version"`
	LogId   Id                     `json:"log_id"`
	Streams []*recordPinStream     `json:"streams"`
	Writers []*recordPinWriterHead `json:"writers"`
}

// A stream's version read through.
type recordPinStream struct {
	SidecarId Id     `json:"sidecar_id"`
	Version   uint64 `json:"version"`
}

// A writer's contiguous head as pinned.
type recordPinWriterHead struct {
	SidecarId Id     `json:"sidecar_id"`
	Seq       uint64 `json:"seq"`
	Leaf      []byte `json:"leaf"`
}

// A log's pins as read from the store, empty when it has none.
type recordPins struct {
	streamVersions map[Id]uint64
	writerHeads    map[Id]RecordChainHead
}

// The pin file of a log.
func recordPinName(logId Id) string {
	return recordPinDirectory + "/" + recordChainIdText(logId)
}

// Reads a log's pins, refusing a file that does not decode: never read as no pins, which would let a stream wind back
// unseen.
func readRecordPins(chain *RecordChainStore, logId Id) (*recordPins, error) {
	pins := &recordPins{streamVersions: map[Id]uint64{}, writerHeads: map[Id]RecordChainHead{}}
	content, err := chain.readFile(recordPinName(logId))
	if err != nil || content == nil {
		return pins, err
	}
	document := &recordPinDocument{}
	if err := recordChainDecode(content, document); err != nil || document.Version != recordPinVersion || document.LogId != logId {
		return nil, fmt.Errorf("%w: pins of log %s", ErrRecordChainCorrupt, logId)
	}
	for _, stream := range document.Streams {
		pins.streamVersions[stream.SidecarId] = stream.Version
	}
	for _, writer := range document.Writers {
		if len(writer.Leaf) != sha256.Size {
			return nil, fmt.Errorf("%w: pins of log %s", ErrRecordChainCorrupt, logId)
		}
		pins.writerHeads[writer.SidecarId] = RecordChainHead{Seq: writer.Seq, Leaf: [sha256.Size]byte(writer.Leaf)}
	}
	return pins, nil
}

// Writes a log's pins, durably.
func writeRecordPins(chain *RecordChainStore, logId Id, pins *recordPins) error {
	document := &recordPinDocument{Version: recordPinVersion, LogId: logId}
	for sidecarId, version := range pins.streamVersions {
		document.Streams = append(document.Streams, &recordPinStream{SidecarId: sidecarId, Version: version})
	}
	for sidecarId, head := range pins.writerHeads {
		document.Writers = append(document.Writers, &recordPinWriterHead{SidecarId: sidecarId, Seq: head.Seq, Leaf: head.Leaf[:]})
	}
	content, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return chain.writeFile(recordPinName(logId), content)
}
