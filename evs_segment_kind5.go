// Kind-5 segments (§11.7's kind 5 row, EVS-FORMAT.md's format 2 chapter): a segment holding exactly one record of one
// versionless version, under a 48 B public header that is format 1's 32 B with format 2, then the 16 B push_id of the
// push that introduces it. In a general repo its object key's 72 B wrapped-key block follows at byte 48 and its record
// at byte 120; in a slot-keyed repo the record starts at byte 48 and names the path's one slot key. Padding, the id
// and the 8 MiB bound are format 1's.
//
// The push_id is what keeps a kind-5 segment its path's: evs answers an upload whose header names another push than
// its ?push= 409 VERSIONING, and marks the receipt of one naming it versionless, so equal bytes are only ever the same
// push's retry and no push adopts another's segment as its own upload. A reader verifies a kind-5 segment as kind 1:
// the id, the header's repo and generation, each frame's AEAD, then content_sha256 and the git oid. A kind-1 locator
// may name a kind-5-headed segment, one adopted as kind 1 when versioning turned on (§11.7's on row), so the format-2
// readers here take either header.
//
// The builder is EvsSegmentBuilder's, streaming as it does: it holds one frame and a pad buffer, never the segment
// (R-EVS-14). It takes one record and refuses a second.
//
// On every leg. Package-level functions are safe for concurrent use; a builder or reader is not.

package sidecar

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The kind-5 header's layout (EVS-FORMAT.md).
const (
	EvsKind5SegmentHeaderByteCount = 48
	evsKind5PushIdOffset           = 32
	// where a general repo's kind-5 record starts: after the header and its wrapped-key block
	evsKind5KeyedRecordOffset = EvsKind5SegmentHeaderByteCount + EvsWrappedKeyByteCount
)

var (
	// Versionless content off §11.7's rules: a kind-5 header naming another push, a citation the cite row does not
	// allow, a staged segment named twice. §11.8's 409 VERSIONING.
	ErrEvsVersioning = errors.New("evs versioning refused")
)

// A kind-5 segment's public header: format 1's fields, and the push that introduces it.
type EvsKind5SegmentHeader struct {
	EvsSegmentHeader
	PushId Id
}

// The 48 bytes: format 2, flags 0, then the push.
func (self *EvsKind5SegmentHeader) encode() []byte {
	encoded := make([]byte, 0, EvsKind5SegmentHeaderByteCount)
	encoded = append(encoded, evsSegmentMagic...)
	encoded = append(encoded, evsSegmentFormat2, 0, 0, 0)
	encoded = append(encoded, self.RepoId[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, self.Generation)
	return append(encoded, self.PushId[:]...)
}

// The header a kind-5 segment's first 48 bytes hold: "URvs" of format 2, flags 0 and the zero bytes zero, a
// generation and a push. A format-1 header is ErrEvsSegmentInvalid here: it is no kind-5 segment.
func ParseEvsKind5SegmentHeader(headerBytes []byte) (*EvsKind5SegmentHeader, error) {
	if len(headerBytes) < EvsKind5SegmentHeaderByteCount || !bytes.HasPrefix(headerBytes, []byte(evsSegmentMagic)) {
		return nil, fmt.Errorf("%w: no kind-5 URvs header", ErrEvsSegmentInvalid)
	}
	if headerBytes[4] != evsSegmentFormat2 {
		return nil, fmt.Errorf("%w: segment format %d where a kind-5 header belongs", ErrEvsSegmentInvalid, headerBytes[4])
	}
	if headerBytes[5] != 0 || headerBytes[6] != 0 || headerBytes[7] != 0 {
		return nil, fmt.Errorf("%w: flags or reserved bytes set", ErrEvsSegmentInvalid)
	}
	header := &EvsKind5SegmentHeader{
		EvsSegmentHeader: EvsSegmentHeader{
			RepoId:     Id(headerBytes[8:24]),
			Generation: binary.BigEndian.Uint64(headerBytes[24:32]),
		},
		PushId: Id(headerBytes[evsKind5PushIdOffset:EvsKind5SegmentHeaderByteCount]),
	}
	if header.Generation == 0 {
		return nil, fmt.Errorf("%w: a segment of no generation", ErrEvsSegmentInvalid)
	}
	if header.PushId == (Id{}) {
		return nil, fmt.Errorf("%w: a kind-5 header naming no push", ErrEvsSegmentInvalid)
	}
	return header, nil
}

// What a format-2 evs checks of an upload's bytes beyond its id (§11.7's kind 5 row, §11.13's receipt row): a
// format-1 header as format 1 checks it, or a kind-5 header, which must name pushId, the upload's ?push= (else
// ErrEvsVersioning); either names repoId, and size is a Padmé length of at most 8 MiB that holds the header. versionless
// is the receipt's mark: true for a kind-5 header. The caller checks the generation against the repo's.
func EvsCheckSegmentUploadFormat2(headerBytes []byte, size uint64, repoId Id, pushId Id) (header *EvsSegmentHeader, versionless bool, err error) {
	if len(headerBytes) < 5 || headerBytes[4] != evsSegmentFormat2 {
		header, err := EvsCheckSegmentUpload(headerBytes, size, repoId)
		return header, false, err
	}
	kind5, err := ParseEvsKind5SegmentHeader(headerBytes)
	if err != nil {
		return nil, false, err
	}
	if kind5.RepoId != repoId {
		return nil, false, fmt.Errorf("%w: a segment of another repo", ErrEvsSegmentInvalid)
	}
	if size < EvsKind5SegmentHeaderByteCount || EvsSegmentMaxByteCount < size || !EvsIsPadme(size) {
		return nil, false, fmt.Errorf("%w: a size of %d bytes", ErrEvsSegmentInvalid, size)
	}
	if kind5.PushId != pushId {
		return nil, false, fmt.Errorf("%w: a kind-5 header naming another push than the upload's", ErrEvsVersioning)
	}
	return &kind5.EvsSegmentHeader, true, nil
}

// A general repo's kind-5 segment for pushId: draws its object key, and writes the 48 B header of manifestKey's
// generation and the key's block under fekKey, of the same generation. It takes one record.
func NewEvsKind5SegmentBuilder(out io.Writer, manifestKey *EvsManifestKey, fekKey *EvsFekKey, pushId Id) (*EvsSegmentBuilder, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if err := fekKey.checkHeld(); err != nil {
		return nil, err
	}
	if fekKey.generation != manifestKey.generation || fekKey.repoId != manifestKey.repoId || manifestKey.deposit {
		return nil, fmt.Errorf("%w: keys of two generations or repos", ErrEvsSegmentInvalid)
	}
	if pushId == (Id{}) {
		return nil, fmt.Errorf("%w: a kind-5 segment naming no push", ErrEvsSegmentInvalid)
	}
	objectKey := NewEvsObjectKey()
	block, err := EvsWrapObjectKey(fekKey, objectKey)
	if err != nil {
		return nil, err
	}
	builder := newEvsSegmentBuilder(out, manifestKey)
	builder.objectKey = objectKey
	builder.kind5PushId = &pushId
	if err := builder.writeStart(block); err != nil {
		return nil, err
	}
	return builder, nil
}

// A slot-keyed repo's kind-5 segment for pushId, of manifestKey's generation: its one record names the path's slot
// key.
func NewEvsSlotKeyedKind5SegmentBuilder(out io.Writer, manifestKey *EvsManifestKey, pushId Id) (*EvsSegmentBuilder, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if pushId == (Id{}) {
		return nil, fmt.Errorf("%w: a kind-5 segment naming no push", ErrEvsSegmentInvalid)
	}
	builder := newEvsSegmentBuilder(out, manifestKey)
	builder.kind5PushId = &pushId
	if err := builder.writeStart(nil); err != nil {
		return nil, err
	}
	return builder, nil
}

// A general repo's segment of either header, as a format-2 reader takes one: its key unwrapped from the block under
// fekKey, of the header's generation.
func NewEvsSegmentReaderFormat2(in io.ReaderAt, size uint64, fekKey *EvsFekKey) (*EvsSegmentReader, error) {
	reader, err := newEvsSegmentReaderFormat2(in, size)
	if err != nil {
		return nil, err
	}
	if err := reader.unwrapKey(fekKey); err != nil {
		return nil, err
	}
	return reader, nil
}

// A slot-keyed segment of either header.
func NewEvsSlotKeyedSegmentReaderFormat2(in io.ReaderAt, size uint64) (*EvsSegmentReader, error) {
	return newEvsSegmentReaderFormat2(in, size)
}

// A reader of a segment whose format-1 or kind-5 header parses, its key not yet unwrapped.
func newEvsSegmentReaderFormat2(in io.ReaderAt, size uint64) (*EvsSegmentReader, error) {
	if size < EvsSegmentHeaderByteCount || EvsSegmentMaxByteCount < size {
		return nil, fmt.Errorf("%w: a segment of %d bytes", ErrEvsSegmentInvalid, size)
	}
	headerBytes := make([]byte, min(size, EvsKind5SegmentHeaderByteCount))
	if _, err := in.ReadAt(headerBytes, 0); err != nil {
		return nil, err
	}
	if headerBytes[4] != evsSegmentFormat2 {
		header, err := ParseEvsSegmentHeader(headerBytes)
		if err != nil {
			return nil, err
		}
		return &EvsSegmentReader{in: in, size: size, header: *header, headerByteCount: EvsSegmentHeaderByteCount, recordReader: NewEvsRecordReader()}, nil
	}
	kind5, err := ParseEvsKind5SegmentHeader(headerBytes)
	if err != nil {
		return nil, err
	}
	pushId := kind5.PushId
	return &EvsSegmentReader{
		in: in, size: size, header: kind5.EvsSegmentHeader, headerByteCount: EvsKind5SegmentHeaderByteCount,
		kind5PushId: &pushId, recordReader: NewEvsRecordReader(),
	}, nil
}

// The push a kind-5 header names, and false for a format-1 header.
func (self *EvsSegmentReader) Kind5PushId() (Id, bool) {
	if self.kind5PushId == nil {
		return Id{}, false
	}
	return *self.kind5PushId, true
}
