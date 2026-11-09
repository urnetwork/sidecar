// A row (§11.14's row; protocol/INDEX-FORMAT.md): what a device shows of a document without its body, the same bytes
// in an entry and in a shard's doc table. Display fields spare every device a query-dependent fetch (owner decision
// 155), so a row carries them cut to their caps and to its own 2 KiB, and encoded from its own document only: no row
// refers to another. Rows are written by any writer of a ref, so every value here is checked on the way in as well as
// the way out.

package sidecar

import (
	"bytes"
	"slices"
	"unicode/utf8"
)

// A row's caps, in bytes. Their sum passes the row's own cap, which is why trimming has an order.
const (
	indexRowMaxByteCount     = 2 * 1024
	indexLocatorMaxByteCount = 512
	indexHeaderMaxByteCount  = 160
	indexFieldMaxByteCount   = 256
)

// A row's flags past its field bits. A provenance bit is the push's, and a private bit a directory document's. Inexact
// says the locator is not the exact path: it was cut, or held bytes that are not UTF-8
// (plan-SEARCH-index-format-bytes#3).
const (
	indexRowTainted uint64 = 1 << 0
	indexRowOutside uint64 = 1 << 1
	indexRowPrivate uint64 = 1 << 2
	indexRowInexact uint64 = 1 << 18
)

// The widest flags encode, bit 18 being the highest: trimming counts this, since a cut it makes may widen them.
const indexRowFlagsMaxByteCount = 3

// An id's bytes: a doc_key, a ref_id, a sidecar_id.
const indexIdByteCount = 16

// A row's fields in their fixed order, for file and mail rows and for the kinds that register fields 6-15. Read only,
// and held here because a row is decoded for every document of a shard.
var (
	indexRowHeaderFields     = []int{indexFieldSubject, indexFieldFrom, indexFieldTo, indexFieldTitle}
	indexRowRegisteredFields = append(slices.Clone(indexRowHeaderFields), 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
)

// What a document is, the row's first byte and SearchHit.doc_kind.
type indexDocKind uint8

const (
	indexDocFile    indexDocKind = 1
	indexDocMail    indexDocKind = 2
	indexDocRecord  indexDocKind = 3
	indexDocDerived indexDocKind = 4
)

// One document's row. Building one sets the numbers, then the text, then calls fit, and from there encoding is exact:
// the encoder and decoder never cut, so a decoded row encodes to its own bytes.
type indexRow struct {
	docKind indexDocKind
	flags   uint64
	// The source's length, a whole file's on each of its chunks' rows.
	byteCount uint64
	chunk     uint64
	// n_d: the size of the document's key set, on a diff's row too.
	trigramCount   uint64
	startedSeconds uint64
	expiresSeconds uint64
	// In ur/index only, where one root serves every branch and stream of the repo.
	refId   []byte
	locator string
	// By §11.14's number. Index 0 and the body's stay empty, and 6-15 hold only what §16.8 and §16.11 register.
	fields [indexFieldLast + 1]string
}

// The bit saying field lost bytes to a cap.
func indexRowCutFlag(field int) uint64 {
	return 1 << (field + 2)
}

// Whether a document of this kind carries fields 6-15.
func (self indexDocKind) hasRegisteredFields() bool {
	return self == indexDocRecord || self == indexDocDerived
}

// A row's fields in their fixed order, which is the order they encode and trim in.
func (self indexDocKind) rowFields() []int {
	if self.hasRegisteredFields() {
		return indexRowRegisteredFields
	}
	return indexRowHeaderFields
}

// Which flag bits a row of this kind may set: bits 0-6 and 18, and on a registered kind those of fields 6-15.
func (self indexDocKind) rowFlags() uint64 {
	if self.hasRegisteredFields() {
		return 1<<19 - 1 - indexRowCutFlag(indexFieldBody)
	}
	return indexRowCutFlag(indexFieldBody) - 1 | indexRowInexact
}

// A field's cap, 1-4 at 160 B and the registered ones at 256 B.
func indexRowFieldCap(field int) int {
	if field <= indexFieldTitle {
		return indexHeaderMaxByteCount
	}
	return indexFieldMaxByteCount
}

// Valid UTF-8 for a row: a value's bytes unchanged if they are, else each ill-formed byte as U+FFFD, as step 1 of
// normalizer 1 reads it. A path may be any bytes, and a row's strings reach SearchHit, which holds only UTF-8.
func indexRowText(value string) string {
	if utf8.ValidString(value) {
		return value
	}
	return string([]rune(value))
}

// The bytes the row encodes to, as its values stand.
func (self *indexRow) encodedByteCount() int {
	byteCount := 1 + indexVByteLength(self.flags) + indexVByteLength(self.byteCount) + indexVByteLength(self.chunk) +
		indexVByteLength(self.trigramCount) + indexVByteLength(self.startedSeconds) +
		indexVByteLength(self.expiresSeconds) + len(self.refId)
	byteCount += indexVByteLength(uint64(len(self.locator))) + len(self.locator)
	for _, field := range self.docKind.rowFields() {
		byteCount += indexVByteLength(uint64(len(self.fields[field]))) + len(self.fields[field])
	}
	return byteCount
}

// Brings the row's text within format (plan-SEARCH-index-format-bytes#3). Each value first goes to its own cap, on a
// code point. If the row still passes 2 KiB, a walk in the fixed order lets each value keep what the row leaves after
// the fixed part and the values before it, every later value counted empty and the flags at their widest. A field that
// loses bytes sets its bit, and a locator that is no longer the exact path sets the inexact bit. Call it once the
// numbers are set, since they share the 2 KiB, and only on values from the document, never on a decoded row.
func (self *indexRow) fit() {
	rowFields := self.docKind.rowFields()
	cutLocator := func(byteCount int) {
		if kept := indexCutUtf8(self.locator, byteCount); len(kept) < len(self.locator) {
			self.locator = kept
			self.flags |= indexRowInexact
		}
	}
	cutField := func(field int, byteCount int) {
		if kept := indexCutUtf8(self.fields[field], byteCount); len(kept) < len(self.fields[field]) {
			self.fields[field] = kept
			self.flags |= indexRowCutFlag(field)
		}
	}
	if text := indexRowText(self.locator); text != self.locator {
		self.locator = text
		self.flags |= indexRowInexact
	}
	cutLocator(indexLocatorMaxByteCount)
	for _, field := range rowFields {
		self.fields[field] = indexRowText(self.fields[field])
		cutField(field, indexRowFieldCap(field))
	}
	if self.encodedByteCount() <= indexRowMaxByteCount {
		return
	}
	used := 1 + indexRowFlagsMaxByteCount + len(self.refId) + indexVByteLength(self.byteCount) +
		indexVByteLength(self.chunk) + indexVByteLength(self.trigramCount) +
		indexVByteLength(self.startedSeconds) + indexVByteLength(self.expiresSeconds)
	// What one value may keep, its own length byte or two taken out, with laterCount values after it.
	roomFor := func(laterCount int) int {
		room := indexRowMaxByteCount - used - laterCount
		if 128 < room {
			return room - 2
		}
		return room - 1
	}
	cutLocator(roomFor(len(rowFields)))
	used += indexVByteLength(uint64(len(self.locator))) + len(self.locator)
	for index, field := range rowFields {
		cutField(field, roomFor(len(rowFields)-index-1))
		used += indexVByteLength(uint64(len(self.fields[field]))) + len(self.fields[field])
	}
}

// Refuses what a row may not hold. Encoder and decoder both run it, so the two can never disagree on the format.
func (self *indexRow) check(companion bool) error {
	if self.docKind < indexDocFile || indexDocDerived < self.docKind {
		return indexMalformed("an unknown doc kind")
	}
	if self.flags&^self.docKind.rowFlags() != 0 {
		return indexMalformed("a row flag this kind cannot set")
	}
	if self.docKind != indexDocDerived && (self.startedSeconds != 0 || self.expiresSeconds != 0) {
		return indexMalformed("times on a row that is not derived")
	}
	if companion && len(self.refId) != indexIdByteCount {
		return indexMalformed("a row in ur/index without its ref_id")
	}
	if !companion && len(self.refId) != 0 {
		return indexMalformed("a ref_id outside ur/index")
	}
	if indexLocatorMaxByteCount < len(self.locator) || !utf8.ValidString(self.locator) {
		return indexMalformed("a locator past its cap or not UTF-8")
	}
	present := [indexFieldLast + 1]bool{}
	for _, field := range self.docKind.rowFields() {
		present[field] = true
		if indexRowFieldCap(field) < len(self.fields[field]) || !utf8.ValidString(self.fields[field]) {
			return indexMalformed("a field past its cap or not UTF-8")
		}
	}
	for field, value := range self.fields {
		if !present[field] && value != "" {
			return indexMalformed("a field this kind does not hold")
		}
	}
	return nil
}

// Appends the row, refusing rather than cutting anything: fit has run, or the row was decoded.
func (self *indexRow) appendEncoded(dst []byte, companion bool) ([]byte, error) {
	if err := self.check(companion); err != nil {
		return nil, err
	}
	start := len(dst)
	dst = append(dst, byte(self.docKind))
	dst = indexAppendVByte(dst, self.flags)
	dst = indexAppendVByte(dst, self.byteCount)
	dst = indexAppendVByte(dst, self.chunk)
	dst = indexAppendVByte(dst, self.trigramCount)
	dst = indexAppendVByte(dst, self.startedSeconds)
	dst = indexAppendVByte(dst, self.expiresSeconds)
	dst = append(dst, self.refId...)
	text := func(value string) {
		dst = indexAppendVByte(dst, uint64(len(value)))
		dst = append(dst, value...)
	}
	text(self.locator)
	for _, field := range self.docKind.rowFields() {
		text(self.fields[field])
	}
	if indexRowMaxByteCount < len(dst)-start {
		return nil, indexMalformed("a row past its cap")
	}
	return dst, nil
}

// One VByte-length text, refused past valueCap before its bytes are touched.
func (self *indexDecoder) text(valueCap int) string {
	length := self.vbyte()
	if uint64(valueCap) < length {
		self.refuse("a text past its cap")
		return ""
	}
	return string(self.take(length))
}

// Reads one row. companion says whether it sits in ur/index, which only its root tells a reader.
func (self *indexDecoder) row(companion bool) *indexRow {
	start := self.remaining()
	row := &indexRow{docKind: indexDocKind(self.oneByte())}
	row.flags = self.vbyte()
	row.byteCount = self.vbyte()
	row.chunk = self.vbyte()
	row.trigramCount = self.vbyte()
	row.startedSeconds = self.vbyte()
	row.expiresSeconds = self.vbyte()
	if companion {
		row.refId = bytes.Clone(self.take(indexIdByteCount))
	}
	row.locator = self.text(indexLocatorMaxByteCount)
	for _, field := range row.docKind.rowFields() {
		row.fields[field] = self.text(indexRowFieldCap(field))
	}
	if self.err != nil {
		return nil
	}
	if indexRowMaxByteCount < start-self.remaining() {
		self.refuse("a row past its cap")
		return nil
	}
	if err := row.check(companion); err != nil {
		self.err = err
		return nil
	}
	return row
}
