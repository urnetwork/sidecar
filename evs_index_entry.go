// An entry (§11.14's entry row; protocol/INDEX-FORMAT.md): one document version's change to the index, or a deletion.
// An entry is encoded from its own document alone, since nothing here may compress across documents: inbound mail
// and collaborators' commits can inject probes (§11.14's codes row). Its version and time are passed in, never read
// from a clock, so devices that build one entry write one set of bytes (FI-22).

package sidecar

import (
	"bytes"
	"cmp"
)

// An entry's first byte, and a shard tombstone table's kind where it is 3 or 4.
type indexEntryKind uint8

const (
	indexEntryFull         indexEntryKind = 1
	indexEntryDiff         indexEntryKind = 2
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
	// Diffs: the base's version, which is below version.
	baseVersion uint64
	// Full entries and diffs.
	row *indexRow
	// Full entries.
	keys indexKeySet
	// Diffs.
	delta indexDelta
}

// An entry's time from its push's signed time_ms. evs keeps that within 10 min of its clock, so it is never before
// the epoch, and a value that were would read as the epoch.
func indexEntrySeconds(signedTimeMs int64) uint64 {
	return uint64(max(signedTimeMs, 0) / 1000)
}

// Refuses what an entry may not hold, for encoder and decoder alike.
func (self *indexEntry) check(companion bool) error {
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
	case indexEntryDiff:
		if self.row == nil {
			return indexMalformed("a diff with no row")
		}
		if self.version <= self.baseVersion {
			return indexMalformed("a diff's base at or above its version")
		}
		if err := self.delta.check(); err != nil {
			return err
		}
		if self.row.trigramCount < uint64(len(self.delta.added)) {
			return indexMalformed("a trigram count below what a diff added")
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
func (self *indexEntry) appendEncoded(dst []byte, companion bool) ([]byte, error) {
	if err := self.check(companion); err != nil {
		return nil, err
	}
	dst = append(dst, byte(self.kind))
	dst = append(dst, self.key[:]...)
	dst = indexAppendVByte(dst, self.version)
	dst = indexAppendVByte(dst, self.timeSeconds)
	var err error
	switch self.kind {
	case indexEntryFull:
		if dst, err = self.row.appendEncoded(dst, companion); err != nil {
			return nil, err
		}
		return self.keys.appendEncoded(dst)
	case indexEntryDiff:
		dst = indexAppendVByte(dst, self.baseVersion)
		if dst, err = self.row.appendEncoded(dst, companion); err != nil {
			return nil, err
		}
		if dst, err = self.delta.added.appendEncoded(dst); err != nil {
			return nil, err
		}
		return self.delta.removed.appendEncoded(dst)
	}
	return dst, nil
}

// Reads one entry.
func (self *indexDecoder) entry(companion bool) *indexEntry {
	entry := &indexEntry{kind: indexEntryKind(self.oneByte())}
	copy(entry.key[:], self.take(indexIdByteCount))
	entry.version = self.vbyte()
	entry.timeSeconds = self.vbyte()
	switch entry.kind {
	case indexEntryFull:
		entry.row = self.row(companion)
		entry.keys = self.keySet()
	case indexEntryDiff:
		entry.baseVersion = self.vbyte()
		entry.row = self.row(companion)
		entry.delta.added = self.keySet()
		entry.delta.removed = self.keySet()
	}
	if self.err != nil {
		return nil
	}
	if err := entry.check(companion); err != nil {
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
