//go:build !ios_extension

// An entry (§11.14's entry and dependency rows; protocol/INDEX-FORMAT.md; owner decision 584): one document version's
// whole key set, or a deletion. An entry is encoded from its own document alone, since nothing here may compress across
// documents: inbound mail and collaborators' commits can inject probes (§11.14's codes row). So no entry rests on
// another, and a reader, a merge or a roll-up takes each as it stands. Its version and time are passed in, never read
// from a clock, so devices that build one entry write one set of bytes (FI-22).

package sidecar

import (
	"bytes"
	"cmp"
)

// An entry's first byte, and a shard tombstone table's kind where it is 3 or 4. Kind 2 was a diff's and stays reserved
// in format 2: no writer writes it, and a decoder refuses it as it refuses any kind it does not know.
type indexEntryKind uint8

const (
	indexEntryFull         indexEntryKind = 1
	indexEntryTombstone    indexEntryKind = 3
	indexEntryRefTombstone indexEntryKind = 4
)

// One entry. Which fields mean anything follows from kind.
type indexEntry struct {
	kind indexEntryKind
	// A doc_key, or a ref tombstone's ref_id.
	key     [indexIdByteCount]byte
	version uint64
	// Seconds of the push's signed time_ms: see indexEntrySeconds.
	timeSeconds uint64
	// Full entries: the document's row and its whole key set.
	row  *indexRow
	keys indexKeySet
}

// An entry's time from its push's signed time_ms. evs keeps that within 10 min of its clock, so it is never before
// the epoch, and a value that were would read as the epoch.
func indexEntrySeconds(signedTimeMs int64) uint64 {
	return uint64(max(signedTimeMs, 0) / 1000)
}

// Refuses what an entry may not hold, for encoder and decoder alike. A full entry whose row and key set D6 skips holds
// a value past its cap, as one whose key set passes KeySetMax does: no honest writer writes one, since D6 made that
// version a tombstone (QD-760). The reserved kind 2 is an unknown kind here.
func (self *indexEntry) check(companion bool, settings *IndexFormatSettings) error {
	switch self.kind {
	case indexEntryFull:
		if self.row == nil {
			return indexMalformed("a full entry with no row")
		}
		if err := self.keys.check(); err != nil {
			return err
		}
		if self.row.trigramCount != uint64(len(self.keys)) {
			return indexMalformed("a trigram count that is not its key set's")
		}
		// the key set's own cap first, then D6's shard test
		if indexKeySetMaxByteCount < len(self.keys) || indexKeySetMaxByteCount < self.keys.encodedByteCount() {
			return indexMalformed("a key set past its cap")
		}
		if indexDocumentPastAShard(self.keys, self.row, settings) {
			return indexMalformed("an entry past a shard")
		}
	case indexEntryTombstone:
	case indexEntryRefTombstone:
		if !companion {
			return indexMalformed("a ref tombstone outside ur/index")
		}
	default:
		return indexMalformed("an unknown entry kind")
	}
	return nil
}

// Appends the entry. A row is encoded here too, so what cannot be decoded cannot be written.
func (self *indexEntry) appendEncoded(dst []byte, companion bool, settings *IndexFormatSettings) ([]byte, error) {
	if err := self.check(companion, settings); err != nil {
		return nil, err
	}
	dst = append(dst, byte(self.kind))
	dst = append(dst, self.key[:]...)
	dst = indexAppendVByte(dst, self.version)
	dst = indexAppendVByte(dst, self.timeSeconds)
	if self.kind == indexEntryFull {
		var err error
		if dst, err = self.row.appendEncoded(dst, companion); err != nil {
			return nil, err
		}
		return self.keys.appendEncoded(dst)
	}
	return dst, nil
}

// Reads one entry. A kind this format does not write, the reserved 2 among them, is refused by check, whatever bytes
// follow it.
func (self *indexDecoder) entry(companion bool, settings *IndexFormatSettings) *indexEntry {
	entry := &indexEntry{kind: indexEntryKind(self.oneByte())}
	copy(entry.key[:], self.take(indexIdByteCount))
	entry.version = self.vbyte()
	entry.timeSeconds = self.vbyte()
	if entry.kind == indexEntryFull {
		entry.row = self.row(companion)
		entry.keys = self.keySet()
	}
	if self.err != nil {
		return nil
	}
	if err := entry.check(companion, settings); err != nil {
		self.err = err
		return nil
	}
	return entry
}

// The one order a slot's entries take (plan-SEARCH-index-format-bytes#2): ascending by 16-byte key, doc_key or ref_id,
// then by kind. It depends only on the entries, so a replaced entry keeps no place and a head is a function of what it
// holds.
func indexCompareEntries(a *indexEntry, b *indexEntry) int {
	return cmp.Or(bytes.Compare(a.key[:], b.key[:]), cmp.Compare(a.kind, b.kind))
}
