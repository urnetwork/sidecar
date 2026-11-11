// The framing every index file with a header shares, and slots and large entries on it (§11.14's slot and large rows;
// protocol/INDEX-FORMAT.md). A slot is one writer's entries, at most IndexFormatSettings.SlotMaxByteCount, 16,208 B, so
// that its record is 16 KiB and rides staged in its push's batch; a large entry is one full entry over
// SlotEntryMaxByteCount, 8 KiB, alone. Both are read by devices that did not
// write them, so a decoder takes the plaintext hash the file's entry version carries, checks it first, and then
// accepts only the one canonical encoding.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A file's first bytes, ahead of its header.
const indexFileMagic = "URix"

// Headers carry these as IndexFileHeader.format and extractor.
const (
	indexFormatVersion = 1
	indexExtractorId   = 1
)

// IndexFileHeader.type.
const (
	indexFileSlot        = 1
	indexFileLargeEntry  = 2
	indexFileBucketShard = 3
	indexFileAllShard    = 4
)

// A file in a newer format is no malformation: it is left unread, and search reads status update (§11.14's off row).
var errIndexNewerFormat = errors.New("index file in a newer format")

// A slot or large entry, decoded or being built. Its header's count and body_length are the encoder's to set.
type indexSlot struct {
	header  *protocol.IndexFileHeader
	entries []*indexEntry
	// Zero bytes after the entries, which an in-place rewrite adds to reach the replaced length.
	padByteCount int
}

// A header's fixed fields, naming the tables this build links. tables are read at run time, so a file says what built
// it (SEARCH-M10-01's trap).
func indexNewFileHeader(fileType uint32, tables indexTables) *protocol.IndexFileHeader {
	return &protocol.IndexFileHeader{
		Format:            indexFormatVersion,
		Type:              fileType,
		Normalizer:        indexNormalizerId,
		Extractor:         indexExtractorId,
		UnicodeVersion:    tables.normVersion,
		TextModuleVersion: tables.textModuleVersion,
	}
}

// Marshals a header as the format has it: deterministically, and a header holds no map, so its fields go out by number.
func indexMarshalHeader(header *protocol.IndexFileHeader) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(header)
}

// Reads the magic and header, leaving the decoder at the body. A header is canonical only if it marshals back to the
// bytes read and holds no field format 1 does not, nested ones included. A format above 1 stops here, before anything
// that format may have changed.
func (self *indexDecoder) fileHeader() *protocol.IndexFileHeader {
	if !bytes.Equal(self.take(uint64(len(indexFileMagic))), []byte(indexFileMagic)) {
		self.refuse("no URix")
	}
	encoded := self.take(self.vbyte())
	if self.err != nil {
		return nil
	}
	header := &protocol.IndexFileHeader{}
	if err := proto.Unmarshal(encoded, header); err != nil {
		self.refuse("a header that does not parse")
		return nil
	}
	if indexFormatVersion < header.Format {
		self.err = errIndexNewerFormat
		return nil
	}
	remarshaled, err := indexMarshalHeader(header)
	if err != nil || !bytes.Equal(remarshaled, encoded) {
		self.refuse("a header that is not canonical")
		return nil
	}
	unknown := len(header.ProtoReflect().GetUnknown())
	for _, coverage := range header.Coverage {
		unknown += len(coverage.ProtoReflect().GetUnknown())
	}
	if unknown != 0 {
		self.refuse("a header with a field format 1 does not have")
		return nil
	}
	return header
}

// Refuses what a slot or large entry's header may not hold, for encoder and decoder alike. Coverage ascends by ref_id,
// then horizon false before true, with at most one row of each kind a ref (DESIGN-DETAILS 1.2.2; QD-689's reading 4).
func indexCheckSlotHeader(header *protocol.IndexFileHeader) error {
	if header.Format != indexFormatVersion {
		return indexMalformed("a header with no format")
	}
	if header.Type != indexFileSlot && header.Type != indexFileLargeEntry {
		return indexMalformed("not a slot or large entry")
	}
	if header.Normalizer == 0 || header.Extractor == 0 || header.UnicodeVersion == "" || header.TextModuleVersion == "" {
		return indexMalformed("a header without its tables")
	}
	if header.BucketDays == 0 || len(header.WriterSidecarId) != indexIdByteCount || header.Seq == 0 {
		return indexMalformed("a header without its bucket or writer")
	}
	if header.PadGeneration != 0 || header.Tombstones != 0 {
		return indexMalformed("a shard's fields on a slot")
	}
	for index, coverage := range header.Coverage {
		if len(coverage.RefId) != indexIdByteCount {
			return indexMalformed("coverage without a ref_id")
		}
		if 0 < index && 0 <= indexCompareCoverage(header.Coverage[index-1], coverage) {
			return indexMalformed("coverage out of order")
		}
	}
	return nil
}

// Coverage's order: by ref_id, then horizon false before true.
func indexCompareCoverage(a *protocol.IndexCoverage, b *protocol.IndexCoverage) int {
	if order := bytes.Compare(a.RefId, b.RefId); order != 0 {
		return order
	}
	switch {
	case a.Horizon == b.Horizon:
		return 0
	case !a.Horizon:
		return -1
	}
	return 1
}

// The most a file of this type may hold, pad included.
func indexSlotFileCap(fileType uint32, settings *IndexFormatSettings) int {
	if fileType == indexFileLargeEntry {
		return settings.LargeMaxByteCount
	}
	return settings.SlotMaxByteCount
}

// Refuses an entry of encoded length byteCount in a file of this type: a slot's stay within SlotEntryMaxByteCount, and
// a large entry's one is over it.
func indexCheckEntrySize(fileType uint32, byteCount int, settings *IndexFormatSettings) error {
	if (fileType == indexFileSlot) != (byteCount <= settings.SlotEntryMaxByteCount) {
		return indexMalformed("an entry the wrong size for its file")
	}
	return nil
}

// Writes a slot or large entry, entries in the format's order, whatever order slot holds them in. Two entries of one
// key are refused, whatever their kinds: a head keeps one per doc_key, and replacing the older one is its writer's to
// do. companion says whether the file is under ur/index's root.
func indexEncodeSlot(slot *indexSlot, companion bool, settings *IndexFormatSettings) ([]byte, error) {
	if slot.padByteCount < 0 {
		return nil, indexMalformed("a rewrite longer than what it replaces")
	}
	entries := slices.Clone(slot.entries)
	slices.SortFunc(entries, indexCompareEntries)
	body := []byte{}
	for index, entry := range entries {
		if 0 < index && entries[index-1].key == entry.key {
			return nil, indexMalformed("an entry key twice in one file")
		}
		start := len(body)
		var err error
		if body, err = entry.appendEncoded(body, companion); err != nil {
			return nil, err
		}
		if err := indexCheckEntrySize(slot.header.Type, len(body)-start, settings); err != nil {
			return nil, err
		}
	}
	if slot.header.Type == indexFileLargeEntry && (len(entries) != 1 || entries[0].kind != indexEntryFull) {
		return nil, indexMalformed("a large entry that is not one full entry")
	}
	header := proto.CloneOf(slot.header)
	header.BodyLength = uint32(len(body))
	header.Count = uint32(len(entries))
	slices.SortFunc(header.Coverage, indexCompareCoverage)
	if err := indexCheckSlotHeader(header); err != nil {
		return nil, err
	}
	encoded, err := indexMarshalHeader(header)
	if err != nil {
		return nil, err
	}
	file := []byte(indexFileMagic)
	file = indexAppendVByte(file, uint64(len(encoded)))
	file = append(file, encoded...)
	file = append(file, body...)
	file = append(file, make([]byte, slot.padByteCount)...)
	if indexSlotFileCap(slot.header.Type, settings) < len(file) {
		return nil, indexMalformed("a file past its cap")
	}
	return file, nil
}

// Reads a slot or large entry. The hash comes first, so tampered bytes reach no parser; then the header, the entries
// in order, and nothing after them but zeros. companion says whether the file is under ur/index's root.
func indexDecodeSlot(file []byte, contentSha256 []byte, companion bool, settings *IndexFormatSettings) (*indexSlot, error) {
	sum := sha256.Sum256(file)
	if !bytes.Equal(sum[:], contentSha256) {
		return nil, indexMalformed("plaintext hash mismatch")
	}
	decoder := indexDecoder{src: file}
	header := decoder.fileHeader()
	if decoder.err != nil {
		return nil, decoder.err
	}
	if err := indexCheckSlotHeader(header); err != nil {
		return nil, err
	}
	if indexSlotFileCap(header.Type, settings) < len(file) {
		return nil, indexMalformed("a file past its cap")
	}
	body := indexDecoder{src: decoder.take(uint64(header.BodyLength))}
	if decoder.err != nil {
		return nil, decoder.err
	}
	for _, b := range decoder.src {
		if b != 0 {
			return nil, indexMalformed("a pad byte that is not zero")
		}
	}
	if header.Type == indexFileLargeEntry && header.Count != 1 {
		return nil, indexMalformed("a large entry not alone")
	}
	slot := &indexSlot{header: header, padByteCount: decoder.remaining()}
	for range header.Count {
		start := body.remaining()
		entry := body.entry(companion)
		if body.err != nil {
			return nil, body.err
		}
		if err := indexCheckEntrySize(header.Type, start-body.remaining(), settings); err != nil {
			return nil, err
		}
		if header.Type == indexFileLargeEntry && entry.kind != indexEntryFull {
			// a diff stands only in a slot, and a large entry's one entry is full (DESIGN-DETAILS 1.2.2)
			return nil, indexMalformed("a large entry that is not one full entry")
		}
		if count := len(slot.entries); 0 < count && 0 <= bytes.Compare(slot.entries[count-1].key[:], entry.key[:]) {
			return nil, indexMalformed("entries out of order or repeated")
		}
		slot.entries = append(slot.entries, entry)
	}
	if body.remaining() != 0 {
		return nil, indexMalformed("bytes past the last entry")
	}
	return slot, nil
}
