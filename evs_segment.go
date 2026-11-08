// Segments (§11.6's segment row): an immutable object of at most 8 MiB holding records, whose id is the SHA-256 of
// all its bytes. A segment is a 32 B public header, "URvs" | format u8 | flags u8 | 2 zero bytes | repo_id |
// u64be(generation); then, in a general repo, the 72 B wrapped-key block of its one object key under fek_g, g the
// header's generation (plan-EVS1-format-bytes#2); then its records; then random bytes to Padmé of its length, so evs
// sees a padded size and nothing finer. Format 1 writes format 1 and flags 0 and refuses anything else; format 2's
// 48 B kind-5 header is refused as FORMAT_UNSUPPORTED. evs checks only the header's repo and generation, the size and
// the id, which the store checks as it streams (§11.13's uploads).
//
// A locator names a record by its offset and length in the segment, so a reader opens just that record and never
// scans; padding is never parsed. A record keyed by the segment's own key names key_ref_kind 0 and the segment's
// generation; in a record-class repo, an inbox or a deposit, the segment carries no block and each record names its
// slot key.
//
// An inline chain (§11.7: a file's chain that pads to at most 16 KiB) keeps its records in its locators instead. Its
// first record's bytes open with the same 72 B block for the chain's key, under fek of the push's generation, and the
// chain's later records use that key; each locator's bytes pad to Padmé of their length with random bytes, as a
// segment does, so an entry version shows no exact record length (EVS-FORMAT.md).
//
// Building and reading both stream: a builder writes as records come and hashes as it writes, holding one frame and
// a pad buffer, and a reader opens a record through an io.ReaderAt, so neither holds a segment (R-EVS-14).
//
// On every leg. Package-level functions are safe for concurrent use; a builder or reader is not.

package sidecar

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.6's segment layout.
const (
	EvsSegmentMaxByteCount    = 8 * 1024 * 1024
	EvsSegmentHeaderByteCount = 32
	// where a general repo's records start: after the header and its wrapped-key block
	evsSegmentKeyedRecordsOffset      = EvsSegmentHeaderByteCount + EvsWrappedKeyByteCount
	evsSegmentMagic                   = "URvs"
	evsSegmentFormat1            byte = 1
	evsSegmentFormat2            byte = 2
	// what a builder writes padding through
	evsSegmentPadBufferByteCount = 4 * 1024
	// the most an inline chain's locator holds, padded (§11.7)
	EvsInlineMaxByteCount = 16 * 1024
)

var (
	// A segment that does not hold §11.6's form, or one a builder cannot write as asked.
	ErrEvsSegmentInvalid = errors.New("evs segment invalid")
	// A record that would take a segment past 8 MiB.
	ErrEvsSegmentFull = errors.New("evs segment full")
)

// A segment's public header: what evs sees of it besides its size and id.
type EvsSegmentHeader struct {
	RepoId     Id
	Generation uint64
}

// The 32 bytes of a format-1 header with flags 0.
func (self *EvsSegmentHeader) encode() []byte {
	encoded := make([]byte, 0, EvsSegmentHeaderByteCount)
	encoded = append(encoded, evsSegmentMagic...)
	encoded = append(encoded, evsSegmentFormat1, 0, 0, 0)
	encoded = append(encoded, self.RepoId[:]...)
	return binary.BigEndian.AppendUint64(encoded, self.Generation)
}

// The header a segment's first 32 bytes hold: format 1 with flags 0 and the zero bytes zero, of a generation.
// Format 2's header is ErrEvsFormatUnsupported; anything else is ErrEvsSegmentInvalid.
func ParseEvsSegmentHeader(headerBytes []byte) (*EvsSegmentHeader, error) {
	if len(headerBytes) < EvsSegmentHeaderByteCount || !bytes.HasPrefix(headerBytes, []byte(evsSegmentMagic)) {
		return nil, fmt.Errorf("%w: no URvs header", ErrEvsSegmentInvalid)
	}
	switch headerBytes[4] {
	case evsSegmentFormat1:
	case evsSegmentFormat2:
		return nil, fmt.Errorf("%w: a kind-5 segment header", ErrEvsFormatUnsupported)
	default:
		return nil, fmt.Errorf("%w: segment format %d", ErrEvsSegmentInvalid, headerBytes[4])
	}
	if headerBytes[5] != 0 || headerBytes[6] != 0 || headerBytes[7] != 0 {
		return nil, fmt.Errorf("%w: flags or reserved bytes set", ErrEvsSegmentInvalid)
	}
	header := &EvsSegmentHeader{
		RepoId:     Id(headerBytes[8:24]),
		Generation: binary.BigEndian.Uint64(headerBytes[24:32]),
	}
	if header.Generation == 0 {
		return nil, fmt.Errorf("%w: a segment of no generation", ErrEvsSegmentInvalid)
	}
	return header, nil
}

// What evs checks of an upload's bytes beyond its id (§11.6, §11.13): the header parses and names repoId, and size is a
// Padmé length of at most 8 MiB that holds the header. The caller checks the generation against the repo's.
func EvsCheckSegmentUpload(headerBytes []byte, size uint64, repoId Id) (*EvsSegmentHeader, error) {
	header, err := ParseEvsSegmentHeader(headerBytes)
	if err != nil {
		return nil, err
	}
	if header.RepoId != repoId {
		return nil, fmt.Errorf("%w: a segment of another repo", ErrEvsSegmentInvalid)
	}
	if size < EvsSegmentHeaderByteCount || EvsSegmentMaxByteCount < size || !EvsIsPadme(size) {
		return nil, fmt.Errorf("%w: a size of %d bytes", ErrEvsSegmentInvalid, size)
	}
	return header, nil
}

// Where a record is in its segment, as its EvsLocator names it.
type EvsRecordPlace struct {
	Offset uint32
	Length uint32
}

// A finished segment: its id, its padded size, and where each record went, in the order they were written.
type EvsSegmentSummary struct {
	Id         [sha256.Size]byte
	PaddedSize uint64
	Places     []EvsRecordPlace
}

// Writes a segment through out as its records come, hashing every byte.
type EvsSegmentBuilder struct {
	out          io.Writer
	digest       hash.Hash
	header       EvsSegmentHeader
	manifestKey  *EvsManifestKey
	objectKey    *EvsObjectKey
	recordWriter *EvsRecordWriter
	length       uint64
	recordStart  uint64
	recordLength uint64
	inRecord     bool
	places       []EvsRecordPlace
	finished     bool
	err          error
}

// What a builder's record writes go through: out and the digest, counted.
type evsSegmentSink struct {
	builder *EvsSegmentBuilder
}

// Writes p to the segment.
func (self evsSegmentSink) Write(p []byte) (int, error) {
	n, err := self.builder.out.Write(p)
	self.builder.digest.Write(p[:n])
	self.builder.length += uint64(n)
	return n, err
}

// A general repo's segment: draws its object key, and writes the header of manifestKey's generation and the key's
// block under fekKey, which must be of the same generation.
func NewEvsSegmentBuilder(out io.Writer, manifestKey *EvsManifestKey, fekKey *EvsFekKey) (*EvsSegmentBuilder, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if err := fekKey.checkHeld(); err != nil {
		return nil, err
	}
	if fekKey.generation != manifestKey.generation || fekKey.repoId != manifestKey.repoId || manifestKey.deposit {
		return nil, fmt.Errorf("%w: keys of two generations or repos", ErrEvsSegmentInvalid)
	}
	objectKey := NewEvsObjectKey()
	block, err := EvsWrapObjectKey(fekKey, objectKey)
	if err != nil {
		return nil, err
	}
	builder := newEvsSegmentBuilder(out, manifestKey)
	builder.objectKey = objectKey
	if err := builder.writeStart(block); err != nil {
		return nil, err
	}
	return builder, nil
}

// A segment whose records each name a slot key, with no block: a record-class repo's, an inbox's or a deposit's, of
// manifestKey's generation.
func NewEvsSlotKeyedSegmentBuilder(out io.Writer, manifestKey *EvsManifestKey) (*EvsSegmentBuilder, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	builder := newEvsSegmentBuilder(out, manifestKey)
	if err := builder.writeStart(nil); err != nil {
		return nil, err
	}
	return builder, nil
}

// A builder of manifestKey's repo and generation with nothing written yet.
func newEvsSegmentBuilder(out io.Writer, manifestKey *EvsManifestKey) *EvsSegmentBuilder {
	return &EvsSegmentBuilder{
		out:          out,
		digest:       sha256.New(),
		header:       EvsSegmentHeader{RepoId: manifestKey.repoId, Generation: manifestKey.generation},
		manifestKey:  manifestKey,
		recordWriter: NewEvsRecordWriter(),
		places:       []EvsRecordPlace{},
	}
}

// Writes the header and the block, if any.
func (self *EvsSegmentBuilder) writeStart(block []byte) error {
	sink := evsSegmentSink{builder: self}
	if _, err := sink.Write(self.header.encode()); err != nil {
		return err
	}
	if block != nil {
		if _, err := sink.Write(block); err != nil {
			return err
		}
	}
	return nil
}

// The segment's object key, nil for a slot-keyed one, which a caller citing the segment from an entry needs nowhere:
// readers unwrap it from the block.
func (self *EvsSegmentBuilder) ObjectKey() *EvsObjectKey {
	return self.objectKey
}

// A record keyed by the segment's own key, for fileId: header's key ref, slot and generation are set here.
func (self *EvsSegmentBuilder) BeginRecord(fileId Id, header *EvsRecordHeader) (io.WriteCloser, error) {
	if self.objectKey == nil {
		return nil, fmt.Errorf("%w: a slot-keyed segment has no key of its own", ErrEvsSegmentInvalid)
	}
	keyed := *header
	keyed.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER
	keyed.SlotId = Id{}
	keyed.KeyIndex = 0
	keyed.Generation = self.header.Generation
	return self.beginRecord(self.manifestKey, self.objectKey, fileId, &keyed)
}

// A record keyed by a slot's key objectKey, which header names by slot_id, key_index and the key's generation, its
// header sealed under manifestKey: the segment's, or a deposit's K_dep of the segment's generation.
func (self *EvsSegmentBuilder) BeginSlotRecord(manifestKey *EvsManifestKey, objectKey *EvsObjectKey, fileId Id, header *EvsRecordHeader) (io.WriteCloser, error) {
	if self.objectKey != nil {
		return nil, fmt.Errorf("%w: a general repo's segment keys its records itself", ErrEvsSegmentInvalid)
	}
	if header.KeyRefKind != protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT {
		return nil, fmt.Errorf("%w: a slot record names no slot", ErrEvsSegmentInvalid)
	}
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if manifestKey.generation != self.header.Generation || manifestKey.repoId != self.header.RepoId {
		return nil, fmt.Errorf("%w: a header key of another generation or repo", ErrEvsSegmentInvalid)
	}
	return self.beginRecord(manifestKey, objectKey, fileId, header)
}

// Begins a record if it fits.
func (self *EvsSegmentBuilder) beginRecord(manifestKey *EvsManifestKey, objectKey *EvsObjectKey, fileId Id, header *EvsRecordHeader) (io.WriteCloser, error) {
	if self.err != nil {
		return nil, self.err
	}
	if self.inRecord || self.finished {
		return nil, fmt.Errorf("%w: a record already open or the segment finished", ErrEvsSegmentInvalid)
	}
	if err := header.check(); err != nil {
		return nil, err
	}
	recordLength := EvsRecordByteCount(header.BodyLength)
	// Padmé never passes the next power of two, and 8 MiB is one, so a length within it pads within it
	if EvsSegmentMaxByteCount < self.length+recordLength {
		return nil, fmt.Errorf("%w: a record of %d bytes after %d", ErrEvsSegmentFull, recordLength, self.length)
	}
	self.recordStart = self.length
	self.recordLength = recordLength
	if err := self.recordWriter.Begin(evsSegmentSink{builder: self}, manifestKey, objectKey, fileId, header); err != nil {
		self.err = err
		return nil, err
	}
	self.inRecord = true
	return evsSegmentRecord{builder: self}, nil
}

// One record of a segment being written.
type evsSegmentRecord struct {
	builder *EvsSegmentBuilder
}

// Takes more of the record's body.
func (self evsSegmentRecord) Write(p []byte) (int, error) {
	n, err := self.builder.recordWriter.Write(p)
	if err != nil {
		self.builder.err = err
	}
	return n, err
}

// Finishes the record and notes its place.
func (self evsSegmentRecord) Close() error {
	builder := self.builder
	if !builder.inRecord {
		return fmt.Errorf("%w: the record is closed", ErrEvsSegmentInvalid)
	}
	builder.inRecord = false
	if err := builder.recordWriter.Close(); err != nil {
		builder.err = err
		return err
	}
	if builder.length-builder.recordStart != builder.recordLength {
		builder.err = fmt.Errorf("%w: a record of %d bytes, not %d", ErrEvsSegmentInvalid, builder.length-builder.recordStart, builder.recordLength)
		return builder.err
	}
	builder.places = append(builder.places, EvsRecordPlace{Offset: uint32(builder.recordStart), Length: uint32(builder.recordLength)})
	return nil
}

// Pads to Padmé of the length with random bytes and gives the segment's id, size and places. A segment holds at least
// one record, and none still open.
func (self *EvsSegmentBuilder) Finish() (*EvsSegmentSummary, error) {
	if self.err != nil {
		return nil, self.err
	}
	if self.inRecord || self.finished || len(self.places) == 0 {
		return nil, fmt.Errorf("%w: a record open, none written, or finished already", ErrEvsSegmentInvalid)
	}
	self.finished = true
	paddedSize := EvsPadme(self.length)
	if err := evsWriteRandom(evsSegmentSink{builder: self}, paddedSize-self.length); err != nil {
		self.err = err
		return nil, err
	}
	return &EvsSegmentSummary{Id: [sha256.Size]byte(self.digest.Sum(nil)), PaddedSize: paddedSize, Places: self.places}, nil
}

// Writes byteCount random bytes through a small buffer.
func evsWriteRandom(out io.Writer, byteCount uint64) error {
	pad := make([]byte, min(byteCount, evsSegmentPadBufferByteCount))
	for 0 < byteCount {
		chunk := pad[:min(byteCount, uint64(len(pad)))]
		// never fails: since Go 1.24 a broken system generator crashes the program instead
		cryptorand.Read(chunk)
		if _, err := out.Write(chunk); err != nil {
			return err
		}
		byteCount -= uint64(len(chunk))
	}
	return nil
}

// The key a slot-keyed record names: its slot, the key's index there and the key's generation, as its header says.
type EvsSlotKeyFunction func(slotId Id, keyIndex uint16, generation uint64) (*EvsObjectKey, error)

// Opens records of one segment by their places, through an io.ReaderAt.
type EvsSegmentReader struct {
	in           io.ReaderAt
	size         uint64
	header       EvsSegmentHeader
	objectKey    *EvsObjectKey
	recordReader *EvsRecordReader
}

// A general repo's segment of size bytes: its header, and its key unwrapped from the block under fekKey, of the
// header's generation.
func NewEvsSegmentReader(in io.ReaderAt, size uint64, fekKey *EvsFekKey) (*EvsSegmentReader, error) {
	reader, err := newEvsSegmentReader(in, size)
	if err != nil {
		return nil, err
	}
	if err := fekKey.checkHeld(); err != nil {
		return nil, err
	}
	if fekKey.generation != reader.header.Generation || fekKey.repoId != reader.header.RepoId {
		return nil, fmt.Errorf("%w: fek of generation %d for a segment of %d", ErrEvsKeyMissing, fekKey.generation, reader.header.Generation)
	}
	if size < evsSegmentKeyedRecordsOffset {
		return nil, fmt.Errorf("%w: no room for a wrapped key", ErrEvsSegmentInvalid)
	}
	block := make([]byte, EvsWrappedKeyByteCount)
	if _, err := in.ReadAt(block, EvsSegmentHeaderByteCount); err != nil {
		return nil, err
	}
	objectKey, err := EvsUnwrapObjectKey(fekKey, block)
	if err != nil {
		return nil, err
	}
	reader.objectKey = objectKey
	return reader, nil
}

// A segment whose records each name a slot key.
func NewEvsSlotKeyedSegmentReader(in io.ReaderAt, size uint64) (*EvsSegmentReader, error) {
	return newEvsSegmentReader(in, size)
}

// A reader of a segment of size bytes whose header parses, its key not yet unwrapped.
func newEvsSegmentReader(in io.ReaderAt, size uint64) (*EvsSegmentReader, error) {
	if size < EvsSegmentHeaderByteCount || EvsSegmentMaxByteCount < size {
		return nil, fmt.Errorf("%w: a segment of %d bytes", ErrEvsSegmentInvalid, size)
	}
	headerBytes := make([]byte, EvsSegmentHeaderByteCount)
	if _, err := in.ReadAt(headerBytes, 0); err != nil {
		return nil, err
	}
	header, err := ParseEvsSegmentHeader(headerBytes)
	if err != nil {
		return nil, err
	}
	return &EvsSegmentReader{in: in, size: size, header: *header, recordReader: NewEvsRecordReader()}, nil
}

// The segment's public header.
func (self *EvsSegmentReader) Header() EvsSegmentHeader {
	return self.header
}

// Opens the record at place: its header under manifestKey, which must be of the segment's generation, held to that
// place's length, then its body under the segment's key or, for a slot-keyed record, the key slotKey gives for what
// the header names. The body's reader is this reader's and serves until the next OpenRecord.
func (self *EvsSegmentReader) OpenRecord(manifestKey *EvsManifestKey, place EvsRecordPlace, fileId Id, slotKey EvsSlotKeyFunction) (*EvsRecordHeader, io.Reader, error) {
	recordsOffset := uint64(EvsSegmentHeaderByteCount)
	if self.objectKey != nil {
		recordsOffset = evsSegmentKeyedRecordsOffset
	}
	if uint64(place.Offset) < recordsOffset || uint64(place.Length) < EvsRecordHeaderByteCount ||
		self.size < uint64(place.Offset)+uint64(place.Length) {
		return nil, nil, fmt.Errorf("%w: a place outside the segment's records", ErrEvsSegmentInvalid)
	}
	sealedHeader := make([]byte, EvsRecordHeaderByteCount)
	if _, err := self.in.ReadAt(sealedHeader, int64(place.Offset)); err != nil {
		return nil, nil, err
	}
	header, err := EvsOpenRecordHeader(manifestKey, sealedHeader)
	if err != nil {
		return nil, nil, err
	}
	if EvsRecordByteCount(header.BodyLength) != uint64(place.Length) {
		return nil, nil, fmt.Errorf("%w: a record of %d bytes at a place of %d", ErrEvsSealInvalid, EvsRecordByteCount(header.BodyLength), place.Length)
	}
	objectKey, err := self.recordKey(header, slotKey)
	if err != nil {
		return nil, nil, err
	}
	body := io.NewSectionReader(self.in, int64(place.Offset)+EvsRecordHeaderByteCount, int64(place.Length)-EvsRecordHeaderByteCount)
	if err := self.recordReader.Begin(body, header, objectKey, self.header.RepoId, fileId); err != nil {
		return nil, nil, err
	}
	return header, self.recordReader, nil
}

// The key header names in this segment.
func (self *EvsSegmentReader) recordKey(header *EvsRecordHeader, slotKey EvsSlotKeyFunction) (*EvsObjectKey, error) {
	switch header.KeyRefKind {
	case protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER:
		if self.objectKey == nil || header.Generation != self.header.Generation {
			return nil, fmt.Errorf("%w: a container-keyed record in a segment with no key of its generation", ErrEvsSealInvalid)
		}
		return self.objectKey, nil
	default:
		if slotKey == nil {
			return nil, fmt.Errorf("%w: a slot-keyed record and no slot keys", ErrEvsKeyMissing)
		}
		return slotKey(header.SlotId, header.KeyIndex, header.Generation)
	}
}

// One inline record's locator bytes: for the chain's first record, a fresh key's block under fekKey and the record;
// for a later one (fekKey nil), the record under the chain's objectKey; either padded to Padmé of its length. The
// header's key ref is set here, and its generation is the chain's: fekKey's for the first record, which a later
// one's caller gives in the header. At most 16 KiB padded (§11.7). Gives the chain's key back.
func EvsSealInlineRecord(manifestKey *EvsManifestKey, fekKey *EvsFekKey, objectKey *EvsObjectKey, fileId Id, header *EvsRecordHeader, body []byte) ([]byte, *EvsObjectKey, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, nil, err
	}
	keyed := *header
	keyed.KeyRefKind = protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER
	keyed.SlotId = Id{}
	keyed.KeyIndex = 0
	keyed.BodyLength = uint64(len(body))
	inline := &bytes.Buffer{}
	if fekKey != nil {
		if err := fekKey.checkHeld(); err != nil {
			return nil, nil, err
		}
		if fekKey.generation != manifestKey.generation || fekKey.repoId != manifestKey.repoId {
			return nil, nil, fmt.Errorf("%w: keys of two generations or repos", ErrEvsRecordInvalid)
		}
		objectKey = NewEvsObjectKey()
		block, err := EvsWrapObjectKey(fekKey, objectKey)
		if err != nil {
			return nil, nil, err
		}
		inline.Write(block)
		keyed.Generation = fekKey.generation
	}
	recordLength := EvsRecordByteCount(keyed.BodyLength)
	if EvsInlineMaxByteCount < EvsPadme(uint64(inline.Len())+recordLength) {
		return nil, nil, fmt.Errorf("%w: an inline record past 16 KiB padded", ErrEvsRecordInvalid)
	}
	writer := NewEvsRecordWriter()
	if err := writer.Begin(inline, manifestKey, objectKey, fileId, &keyed); err != nil {
		return nil, nil, err
	}
	if _, err := writer.Write(body); err != nil {
		return nil, nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, nil, err
	}
	if err := evsWriteRandom(inline, EvsPadme(uint64(inline.Len()))-uint64(inline.Len())); err != nil {
		return nil, nil, err
	}
	return inline.Bytes(), objectKey, nil
}

// An inline record's header and body from its locator bytes: the chain's first (fekKey given, objectKey nil), whose
// block gives the chain's key, or a later one under the chain's objectKey. Gives the chain's key back.
func EvsOpenInlineRecord(manifestKey *EvsManifestKey, fekKey *EvsFekKey, objectKey *EvsObjectKey, fileId Id, inline []byte) (*EvsRecordHeader, []byte, *EvsObjectKey, error) {
	if EvsInlineMaxByteCount < len(inline) || !EvsIsPadme(uint64(len(inline))) {
		return nil, nil, nil, fmt.Errorf("%w: inline bytes of %d", ErrEvsSealInvalid, len(inline))
	}
	rest := inline
	if fekKey != nil {
		if len(rest) < EvsWrappedKeyByteCount {
			return nil, nil, nil, fmt.Errorf("%w: no wrapped key", ErrEvsSealInvalid)
		}
		unwrapped, err := EvsUnwrapObjectKey(fekKey, rest[:EvsWrappedKeyByteCount])
		if err != nil {
			return nil, nil, nil, err
		}
		objectKey = unwrapped
		rest = rest[EvsWrappedKeyByteCount:]
	}
	if len(rest) < EvsRecordHeaderByteCount {
		return nil, nil, nil, fmt.Errorf("%w: no record header", ErrEvsSealInvalid)
	}
	header, err := EvsOpenRecordHeader(manifestKey, rest[:EvsRecordHeaderByteCount])
	if err != nil {
		return nil, nil, nil, err
	}
	if header.KeyRefKind != protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER || (fekKey != nil && header.Generation != fekKey.generation) {
		return nil, nil, nil, fmt.Errorf("%w: an inline record not keyed by its chain", ErrEvsSealInvalid)
	}
	recordLength := EvsRecordByteCount(header.BodyLength)
	if uint64(len(rest)) < recordLength {
		return nil, nil, nil, fmt.Errorf("%w: the record runs past its locator", ErrEvsSealInvalid)
	}
	reader := NewEvsRecordReader()
	if err := reader.Begin(bytes.NewReader(rest[EvsRecordHeaderByteCount:recordLength]), header, objectKey, manifestKey.repoId, fileId); err != nil {
		return nil, nil, nil, err
	}
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, nil, err
	}
	return header, body, objectKey, nil
}
