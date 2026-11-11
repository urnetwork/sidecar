// Records (§11.6's record row): a checkpoint, a diff against the file's previous version, or a 4 MiB chunk of a large
// file, each a 160 B sealed header and then its body in 64 KiB STREAM frames, as in age.
//
// The header is 24 B nonce | 120 B sealed | 16 B tag, XChaCha20-Poly1305 under manifest_g (a deposit's K_dep), g the
// segment header's generation or an inline record's push generation, AAD "UR evs 1.0 record" || repo_id || u64be(g)
// (plan-EVS1-format-bytes#3). Its 120 bytes, integers big-endian: record_id 16 | base_record_id 16, zero unless a diff
// | oid 32, SHA-1 left-aligned and zero-filled | slot_id 16, zero unless key_ref_kind 1 | generation 8 | body_length 8
// | key_index 2 | kind 1 | key_ref_kind 1 | oid_kind 1 | nonce_prefix 19. generation is the one the body frames'
// AAD names: the container's g for key_ref_kind 0, whose key is the segment's or inline chain's wrapped-key block,
// and the slot key's own generation for key_ref_kind 1, so a reader holds the key to the generation it was written
// under (EVS-FORMAT.md).
//
// The body is max(1, ceil(body_length / 64 KiB)) frames, each its plaintext sealed under the object key with nonce
// nonce_prefix || u32be(frame index) || a final-flag byte, 1 on the last frame and 0 on every other, and AAD repo_id
// || file_id || record_id || u64be(generation) || u32be(frame index). file_id comes from the entry's sealed fields,
// so a record cannot be moved to another file, and the frame counter and final flag make a swapped, dropped or
// truncated frame fail its tag. Every frame but the last is full; the last is the remainder, empty only when the
// whole body is.
//
// Both directions stream: a writer or reader holds one frame, 64 KiB and a tag, whatever the body's length, and
// releases a frame's plaintext only once its tag verifies, so tampering fails before plaintext (R-EVS-14, §11.15).
// A body is at most 8 MiB, since a record lives in a segment or inline. evs checks nothing of a record.
//
// On every leg. Package-level functions are safe for concurrent use; an EvsRecordWriter or EvsRecordReader is not.

package sidecar

import (
	"crypto/cipher"
	cryptorand "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.6's record layout.
const (
	EvsRecordHeaderByteCount = chacha20poly1305.NonceSizeX + evsRecordSealedByteCount + chacha20poly1305.Overhead
	// a body frame's plaintext, all but the last
	EvsRecordFrameByteCount = 64 * 1024
	// a record body's bound: it lives in a segment of at most 8 MiB, or inline
	EvsRecordMaxBodyLength = 8 * 1024 * 1024

	evsRecordSealedByteCount      = 120
	evsRecordNoncePrefixByteCount = 19
	evsRecordAadLabel             = "UR evs 1.0 record"
	// repo_id, file_id, record_id, u64 generation and u32 frame index
	evsRecordFrameAadByteCount = 16 + 16 + 16 + 8 + 4
	// the final-flag byte's values
	evsRecordFrameMore  byte = 0
	evsRecordFrameFinal byte = 1
)

// A record that cannot be written as asked.
var ErrEvsRecordInvalid = errors.New("evs record invalid")

// A record header's sealed fields (plan-EVS1-format-bytes#3).
type EvsRecordHeader struct {
	RecordId Id
	// the record a diff applies to; zero for any other kind
	BaseRecordId Id
	// the git oid of the file this record gives, SHA-1 left-aligned and zero-filled
	Oid [32]byte
	// key_ref_kind 1: the slot holding its key; else zero
	SlotId Id
	// the generation its frames' AAD names (above)
	Generation uint64
	// the body's plaintext length
	BodyLength uint64
	// key_ref_kind 1: the key's index in its slot; else zero
	KeyIndex   uint16
	Kind       protocol.EvsRecordKind
	KeyRefKind protocol.EvsKeyRefKind
	OidKind    protocol.EvsOidKind
	// the frames' nonce prefix, drawn for each record by its writer
	NoncePrefix [evsRecordNoncePrefixByteCount]byte
}

// The header held to format 1: a kind and key ref §11.6 names, a slot only for a slot key, a base only for a diff,
// which a history diff leaves zero,
// a SHA-1 oid (v0 writes and reads SHA-1 only, plan-EVS1-format-bytes#4), a generation, and a body a record can
// carry.
func (self *EvsRecordHeader) check() error {
	switch self.Kind {
	case protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT, protocol.EvsRecordKind_EVS_RECORD_CHUNK:
		if self.BaseRecordId != (Id{}) {
			return fmt.Errorf("%w: a base record outside a diff", ErrEvsRecordInvalid)
		}
	case protocol.EvsRecordKind_EVS_RECORD_DIFF:
		// a diff in an entry's chain names the record it applies to, which the chain's walk holds it to; a history
		// diff's base_record_id is zero, its base named by oid in the sealed metadata (DESIGN-DETAILS 8.2.2's history
		// row)
	default:
		return fmt.Errorf("%w: record kind %d", ErrEvsRecordInvalid, self.Kind)
	}
	switch self.KeyRefKind {
	case protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER:
		if self.SlotId != (Id{}) || self.KeyIndex != 0 {
			return fmt.Errorf("%w: a slot on a container-keyed record", ErrEvsRecordInvalid)
		}
	case protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT:
		if self.SlotId == (Id{}) || EvsSlotMaxKeyCount <= self.KeyIndex {
			return fmt.Errorf("%w: a slot-keyed record names no key", ErrEvsRecordInvalid)
		}
	default:
		return fmt.Errorf("%w: key ref kind %d", ErrEvsRecordInvalid, self.KeyRefKind)
	}
	if self.OidKind != protocol.EvsOidKind_EVS_OID_SHA1 {
		return fmt.Errorf("%w: an oid that is not SHA-1", ErrEvsRecordInvalid)
	}
	for _, b := range self.Oid[len(EvsGitOid{}):] {
		if b != 0 {
			return fmt.Errorf("%w: a SHA-1 oid not zero-filled", ErrEvsRecordInvalid)
		}
	}
	if self.Generation == 0 {
		return fmt.Errorf("%w: a record of no generation", ErrEvsRecordInvalid)
	}
	if EvsRecordMaxBodyLength < self.BodyLength {
		return fmt.Errorf("%w: a body of %d bytes", ErrEvsRecordInvalid, self.BodyLength)
	}
	return nil
}

// The 120 sealed bytes.
func (self *EvsRecordHeader) encode() []byte {
	encoded := make([]byte, 0, evsRecordSealedByteCount)
	encoded = append(encoded, self.RecordId[:]...)
	encoded = append(encoded, self.BaseRecordId[:]...)
	encoded = append(encoded, self.Oid[:]...)
	encoded = append(encoded, self.SlotId[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, self.Generation)
	encoded = binary.BigEndian.AppendUint64(encoded, self.BodyLength)
	encoded = binary.BigEndian.AppendUint16(encoded, self.KeyIndex)
	encoded = append(encoded, byte(self.Kind), byte(self.KeyRefKind), byte(self.OidKind))
	return append(encoded, self.NoncePrefix[:]...)
}

// The header 120 sealed bytes hold, held to format 1.
func decodeEvsRecordHeader(encoded []byte) (*EvsRecordHeader, error) {
	if len(encoded) != evsRecordSealedByteCount {
		return nil, fmt.Errorf("%w: a header of %d bytes", ErrEvsSealInvalid, len(encoded))
	}
	header := &EvsRecordHeader{
		RecordId:     Id(encoded[0:16]),
		BaseRecordId: Id(encoded[16:32]),
		Oid:          [32]byte(encoded[32:64]),
		SlotId:       Id(encoded[64:80]),
		Generation:   binary.BigEndian.Uint64(encoded[80:88]),
		BodyLength:   binary.BigEndian.Uint64(encoded[88:96]),
		KeyIndex:     binary.BigEndian.Uint16(encoded[96:98]),
		Kind:         protocol.EvsRecordKind(encoded[98]),
		KeyRefKind:   protocol.EvsKeyRefKind(encoded[99]),
		OidKind:      protocol.EvsOidKind(encoded[100]),
		NoncePrefix:  [evsRecordNoncePrefixByteCount]byte(encoded[101:120]),
	}
	if err := header.check(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsSealInvalid, err)
	}
	return header, nil
}

// The number of frames a body of bodyLength bytes takes: max(1, ceil(bodyLength / 64 KiB)).
func EvsRecordFrameCount(bodyLength uint64) uint64 {
	if bodyLength == 0 {
		return 1
	}
	return (bodyLength + EvsRecordFrameByteCount - 1) / EvsRecordFrameByteCount
}

// A whole record's bytes, header and sealed frames, for a body of bodyLength bytes: what its locator's length is.
func EvsRecordByteCount(bodyLength uint64) uint64 {
	return EvsRecordHeaderByteCount + bodyLength + chacha20poly1305.Overhead*EvsRecordFrameCount(bodyLength)
}

// The 160 B header sealed under manifestKey, with header held to format 1.
func EvsSealRecordHeader(manifestKey *EvsManifestKey, header *EvsRecordHeader) ([]byte, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if err := header.check(); err != nil {
		return nil, err
	}
	return evsSeal(manifestKey.key, header.encode(), evsLabeledAad(evsRecordAadLabel, manifestKey.repoId, manifestKey.generation))
}

// The header a 160 B sealed header holds under manifestKey, or ErrEvsSealInvalid.
func EvsOpenRecordHeader(manifestKey *EvsManifestKey, sealed []byte) (*EvsRecordHeader, error) {
	if err := manifestKey.checkHeld(); err != nil {
		return nil, err
	}
	if len(sealed) != EvsRecordHeaderByteCount {
		return nil, fmt.Errorf("%w: a sealed header of %d bytes", ErrEvsSealInvalid, len(sealed))
	}
	encoded, err := evsOpen(manifestKey.key, sealed, evsLabeledAad(evsRecordAadLabel, manifestKey.repoId, manifestKey.generation))
	if err != nil {
		return nil, err
	}
	return decodeEvsRecordHeader(encoded)
}

// What a record's frames share: the object key's AEAD, the nonce and AAD each frame rewrites the tail of, and where
// the frames stand.
type evsRecordFrames struct {
	aead       cipher.AEAD
	nonce      [chacha20poly1305.NonceSizeX]byte
	aad        [evsRecordFrameAadByteCount]byte
	frameIndex uint32
	frameCount uint64
}

// Ready for frame 0 of a record with header's prefix, record id, generation and length, in repoId's file fileId.
func (self *evsRecordFrames) begin(objectKey *EvsObjectKey, repoId Id, fileId Id, header *EvsRecordHeader) error {
	if err := objectKey.checkHeld(); err != nil {
		return err
	}
	aead, err := chacha20poly1305.NewX(objectKey.key)
	if err != nil {
		return fmt.Errorf("evs: record aead: %w", err)
	}
	self.aead = aead
	copy(self.nonce[:evsRecordNoncePrefixByteCount], header.NoncePrefix[:])
	copy(self.aad[0:16], repoId[:])
	copy(self.aad[16:32], fileId[:])
	copy(self.aad[32:48], header.RecordId[:])
	binary.BigEndian.PutUint64(self.aad[48:56], header.Generation)
	self.frameIndex = 0
	self.frameCount = EvsRecordFrameCount(header.BodyLength)
	return nil
}

// Points the nonce and AAD at the current frame.
func (self *evsRecordFrames) frame() {
	final := evsRecordFrameMore
	if uint64(self.frameIndex)+1 == self.frameCount {
		final = evsRecordFrameFinal
	}
	binary.BigEndian.PutUint32(self.nonce[evsRecordNoncePrefixByteCount:], self.frameIndex)
	self.nonce[len(self.nonce)-1] = final
	binary.BigEndian.PutUint32(self.aad[56:60], self.frameIndex)
}

// Writes records one after another, holding one frame. Begin starts a record, Write takes its body and Close seals
// its last frame; then Begin may start the next, reusing the frame.
type EvsRecordWriter struct {
	out    io.Writer
	header EvsRecordHeader
	frames evsRecordFrames
	// the current frame's plaintext, sealed in place, so its capacity holds a tag too
	frame   []byte
	written uint64
	open    bool
	err     error
}

// A writer with its one frame and no record begun.
func NewEvsRecordWriter() *EvsRecordWriter {
	return &EvsRecordWriter{frame: make([]byte, 0, EvsRecordFrameByteCount+chacha20poly1305.Overhead)}
}

// Begins a record on out: draws its nonce prefix, writes its header sealed under manifestKey, and makes ready to seal
// its body under objectKey for fileId. header's prefix is ignored and drawn here; the header as written is
// Header's.
func (self *EvsRecordWriter) Begin(out io.Writer, manifestKey *EvsManifestKey, objectKey *EvsObjectKey, fileId Id, header *EvsRecordHeader) error {
	if self.open {
		return fmt.Errorf("%w: a record already begun", ErrEvsRecordInvalid)
	}
	self.header = *header
	// never fails: since Go 1.24 a broken system generator crashes the program instead
	cryptorand.Read(self.header.NoncePrefix[:])
	sealed, err := EvsSealRecordHeader(manifestKey, &self.header)
	if err != nil {
		return err
	}
	if err := self.frames.begin(objectKey, manifestKey.repoId, fileId, &self.header); err != nil {
		return err
	}
	if _, err := out.Write(sealed); err != nil {
		return err
	}
	self.out = out
	self.frame = self.frame[:0]
	self.written = 0
	self.open = true
	self.err = nil
	return nil
}

// The header as written, its nonce prefix drawn.
func (self *EvsRecordWriter) Header() EvsRecordHeader {
	return self.header
}

// Seals the buffered frame and writes it out.
func (self *EvsRecordWriter) sealFrame() error {
	self.frames.frame()
	sealed := self.frames.aead.Seal(self.frame[:0], self.frames.nonce[:], self.frame, self.frames.aad[:])
	if _, err := self.out.Write(sealed); err != nil {
		return err
	}
	self.frames.frameIndex += 1
	self.frame = self.frame[:0]
	return nil
}

// Takes more of the body, sealing each frame once it is full and more follows. Refuses past body_length.
func (self *EvsRecordWriter) Write(p []byte) (int, error) {
	if !self.open {
		return 0, fmt.Errorf("%w: no record begun", ErrEvsRecordInvalid)
	}
	if self.err != nil {
		return 0, self.err
	}
	if self.header.BodyLength-self.written < uint64(len(p)) {
		self.err = fmt.Errorf("%w: more than the body's %d bytes", ErrEvsRecordInvalid, self.header.BodyLength)
		return 0, self.err
	}
	taken := 0
	for taken < len(p) {
		if len(self.frame) == EvsRecordFrameByteCount {
			if err := self.sealFrame(); err != nil {
				self.err = err
				return taken, err
			}
		}
		n := min(EvsRecordFrameByteCount-len(self.frame), len(p)-taken)
		self.frame = append(self.frame, p[taken:taken+n]...)
		taken += n
		self.written += uint64(n)
	}
	return taken, nil
}

// Seals the last frame. Refuses a body shorter than body_length, whose record then stands unfinished and must not be
// kept.
func (self *EvsRecordWriter) Close() error {
	if !self.open {
		return fmt.Errorf("%w: no record begun", ErrEvsRecordInvalid)
	}
	self.open = false
	if self.err != nil {
		return self.err
	}
	if self.written != self.header.BodyLength {
		return fmt.Errorf("%w: a body of %d bytes, not %d", ErrEvsRecordInvalid, self.written, self.header.BodyLength)
	}
	return self.sealFrame()
}

// Reads record bodies one after another, holding one frame. Begin starts a record from its opened header; Read gives
// its plaintext frame by frame, each only once its tag verifies, and io.EOF after the last frame, whose final flag
// is checked; a body cut short is ErrEvsSealInvalid, never an early end.
type EvsRecordReader struct {
	in     io.Reader
	frames evsRecordFrames
	// the current frame, opened in place; plaintext not yet read is frame[at:]
	frame     []byte
	at        int
	remaining uint64
	done      bool
	err       error
}

// A reader with its one frame and no record begun.
func NewEvsRecordReader() *EvsRecordReader {
	return &EvsRecordReader{frame: make([]byte, 0, EvsRecordFrameByteCount+chacha20poly1305.Overhead)}
}

// Begins the body of the record whose opened header is header, read from in, which holds the body's frames and may
// end there; objectKey is the key header names, and repoId and fileId the AAD's.
func (self *EvsRecordReader) Begin(in io.Reader, header *EvsRecordHeader, objectKey *EvsObjectKey, repoId Id, fileId Id) error {
	if err := header.check(); err != nil {
		return err
	}
	if err := self.frames.begin(objectKey, repoId, fileId, header); err != nil {
		return err
	}
	self.in = in
	self.frame = self.frame[:0]
	self.at = 0
	self.remaining = header.BodyLength
	self.done = false
	self.err = nil
	return nil
}

// Reads and opens the next frame.
func (self *EvsRecordReader) openFrame() error {
	plaintextLength := min(uint64(EvsRecordFrameByteCount), self.remaining)
	if uint64(self.frames.frameIndex)+1 < self.frames.frameCount && plaintextLength != EvsRecordFrameByteCount {
		return fmt.Errorf("%w: a frame short of 64 KiB before the last", ErrEvsSealInvalid)
	}
	sealed := self.frame[:plaintextLength+chacha20poly1305.Overhead]
	if _, err := io.ReadFull(self.in, sealed); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: the record is cut short at frame %d", ErrEvsSealInvalid, self.frames.frameIndex)
		}
		return err
	}
	self.frames.frame()
	plaintext, err := self.frames.aead.Open(sealed[:0], self.frames.nonce[:], sealed, self.frames.aad[:])
	if err != nil {
		return fmt.Errorf("%w: frame %d does not open", ErrEvsSealInvalid, self.frames.frameIndex)
	}
	self.frame = plaintext
	self.at = 0
	self.remaining -= uint64(len(plaintext))
	self.frames.frameIndex += 1
	if uint64(self.frames.frameIndex) == self.frames.frameCount {
		self.done = true
	}
	return nil
}

// The body's plaintext, frame by frame.
func (self *EvsRecordReader) Read(p []byte) (int, error) {
	if self.err != nil {
		return 0, self.err
	}
	for self.at == len(self.frame) {
		if self.done {
			return 0, io.EOF
		}
		if self.in == nil {
			return 0, fmt.Errorf("%w: no record begun", ErrEvsRecordInvalid)
		}
		if err := self.openFrame(); err != nil {
			self.err = err
			return 0, err
		}
	}
	n := copy(p, self.frame[self.at:])
	self.at += n
	return n, nil
}
