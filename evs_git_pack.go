//go:build !ios_extension

// The object sink's pack (DESIGN-DETAILS 8.2.7's sink): gitformat-pack's version 2, every object whole, never
// deltified, each zlib-compressed after its type and size header, the object count in the pack's header and a SHA-1
// of every byte before it in its trailer. git index-pack takes such a pack whole and hashes every object again as it
// stores it, so a byte the sink got wrong fails there.
//
// Objects go into a spool as they come, so memory holds only the index of the pending oids and the small objects a
// replay reads back before the flush (trees, commits and tags); the pack is written out whole at a flush, its header
// carrying the count, and the spool starts again. The local tier's flush runs git index-pack --stdin on it into the
// mount's bare repository (EVS1-M2-35); the spool is whatever the caller gives, a file in the local tier.
//
// On every leg but the forwarding role's. An EvsGitPackSink is one replay's, not safe for concurrent use.

package sidecar

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// gitformat-pack's object types.
const (
	evsGitPackCommit = 1
	evsGitPackTree   = 2
	evsGitPackBlob   = 3
	evsGitPackTag    = 4
)

// The pack type of an object kind.
func evsGitPackType(kind string) (byte, error) {
	switch kind {
	case evsGitCommitKind:
		return evsGitPackCommit, nil
	case evsGitTreeKind:
		return evsGitPackTree, nil
	case evsGitBlobKind:
		return evsGitPackBlob, nil
	case evsGitTagKind:
		return evsGitPackTag, nil
	}
	return 0, fmt.Errorf("%w: an object of kind %q", ErrEvsGitObjectInvalid, kind)
}

// A pack's spool: written at increasing offsets as objects come, read from its start at a flush, then cut back.
// Writes are positioned, so a file's offset, which a truncation does not move, never decides where bytes land; an
// *os.File serves.
type EvsGitPackSpool interface {
	io.WriterAt
	io.ReaderAt
	// Cuts the spool to size bytes: 0 for the next pack, or back past an entry that is not kept.
	Truncate(size int64) error
}

// A version 2 pack of whole objects over a spool.
type EvsGitPackWriter struct {
	spool     EvsGitPackSpool
	count     uint32
	byteCount int64
}

// An empty pack over spool, which it writes from offset 0.
func NewEvsGitPackWriter(spool EvsGitPackSpool) *EvsGitPackWriter {
	return &EvsGitPackWriter{spool: spool}
}

// The objects added since the pack started.
func (self *EvsGitPackWriter) Count() uint32 {
	return self.count
}

// The bytes the entries added since the pack started take in the spool.
func (self *EvsGitPackWriter) ByteCount() int64 {
	return self.byteCount
}

// gitformat-pack's entry header: type in bits 4 to 6 of the first byte and the size's low 4 bits below them, the
// rest of the size 7 bits a byte, low first, each byte but the last with its high bit set.
func evsGitPackEntryHeader(packType byte, size int64) []byte {
	header := []byte{packType<<4 | byte(size&0x0f)}
	size >>= 4
	for 0 < size {
		header[len(header)-1] |= 0x80
		header = append(header, byte(size&0x7f))
		size >>= 7
	}
	return header
}

// Adds an object of kind and size from content, compressed into the spool, and answers its oid, hashed as it is read.
// An entry that fails part way is cut from the spool, so the pack holds only whole entries.
func (self *EvsGitPackWriter) Add(kind string, content io.Reader, size int64) (EvsGitOid, error) {
	packType, err := evsGitPackType(kind)
	if err != nil {
		return EvsGitOid{}, err
	}
	if size < 0 {
		return EvsGitOid{}, fmt.Errorf("%w: an object of %d bytes", ErrEvsGitObjectInvalid, size)
	}
	start := self.byteCount
	oid, entryByteCount, err := func() (EvsGitOid, int64, error) {
		entry := &evsOffsetWriter{spool: self.spool, offset: start}
		if _, err := entry.Write(evsGitPackEntryHeader(packType, size)); err != nil {
			return EvsGitOid{}, 0, err
		}
		digest := sha1.New()
		digest.Write(fmt.Appendf(nil, "%s %d\x00", kind, size))
		compressor := zlib.NewWriter(entry)
		copied, err := io.Copy(io.MultiWriter(compressor, digest), content)
		if err != nil {
			return EvsGitOid{}, 0, err
		}
		if copied != size {
			return EvsGitOid{}, 0, fmt.Errorf("%w: an object of %d bytes where %d were promised", ErrEvsGitObjectInvalid, copied, size)
		}
		if err := compressor.Close(); err != nil {
			return EvsGitOid{}, 0, err
		}
		return EvsGitOid(digest.Sum(nil)), entry.offset - start, nil
	}()
	if err != nil {
		return EvsGitOid{}, errors.Join(err, self.spool.Truncate(start))
	}
	self.count += 1
	self.byteCount += entryByteCount
	return oid, nil
}

// Takes back the last entry Add made, of entryByteCount bytes ending the spool.
func (self *EvsGitPackWriter) dropLast(entryByteCount int64) error {
	self.count -= 1
	self.byteCount -= entryByteCount
	return self.spool.Truncate(self.byteCount)
}

// Writes the pack to out: "PACK", version 2, the count, every entry as added, and the SHA-1 of all of it.
func (self *EvsGitPackWriter) WriteTo(out io.Writer) (int64, error) {
	digest := sha1.New()
	written := &evsCountingWriter{writer: io.MultiWriter(out, digest)}
	header := append([]byte("PACK"), 0, 0, 0, 2)
	header = binary.BigEndian.AppendUint32(header, self.count)
	if _, err := written.Write(header); err != nil {
		return written.count, err
	}
	if _, err := io.Copy(written, io.NewSectionReader(self.spool, 0, self.byteCount)); err != nil {
		return written.count, err
	}
	if _, err := out.Write(digest.Sum(nil)); err != nil {
		return written.count, err
	}
	return written.count + sha1.Size, nil
}

// Starts the pack again, empty.
func (self *EvsGitPackWriter) Reset() error {
	self.count = 0
	self.byteCount = 0
	return self.spool.Truncate(0)
}

// A writer that counts what it passes on.
type evsCountingWriter struct {
	writer io.Writer
	count  int64
}

// Passes p on, counting what was written.
func (self *evsCountingWriter) Write(p []byte) (int, error) {
	n, err := self.writer.Write(p)
	self.count += int64(n)
	return n, err
}

// A writer at a spool's offset, which moves on as it writes.
type evsOffsetWriter struct {
	spool  io.WriterAt
	offset int64
}

// Writes p at the offset, then moves the offset past it.
func (self *evsOffsetWriter) Write(p []byte) (int, error) {
	n, err := self.spool.WriteAt(p, self.offset)
	self.offset += int64(n)
	return n, err
}

// What a pack's flush does with it: the local tier's runs git index-pack --stdin into its bare repository.
type EvsGitPackFlush func(ctx context.Context, pack io.Reader) error

// An object sink over packs (EvsGitObjectSink): objects added to a pack until chunkByteCount of entries, then the
// pack flushed through flush and started again, so a replay's memory is the pending objects' index and the small
// objects it may read back. held answers whether the repository holds an object already, which is not written again.
type EvsGitPackSink struct {
	writer         *EvsGitPackWriter
	flush          EvsGitPackFlush
	held           func(oid EvsGitOid) bool
	chunkByteCount int64
	// the pending objects' kinds, and the bytes of the trees, commits and tags among them
	pending      map[EvsGitOid]string
	pendingBytes map[EvsGitOid][]byte
}

// A sink adding to spool's packs, flushing each at chunkByteCount (ObjectSinkChunkByteCount) through flush.
func NewEvsGitPackSink(spool EvsGitPackSpool, flush EvsGitPackFlush, held func(oid EvsGitOid) bool, chunkByteCount int64) *EvsGitPackSink {
	return &EvsGitPackSink{
		writer: NewEvsGitPackWriter(spool), flush: flush, held: held, chunkByteCount: chunkByteCount,
		pending: map[EvsGitOid]string{}, pendingBytes: map[EvsGitOid][]byte{},
	}
}

// Adds an object whose bytes are in memory unless the sink holds it; a tree, commit or tag stays readable until
// the flush.
func (self *EvsGitPackSink) WriteGitObject(kind string, content []byte) (EvsGitOid, error) {
	oid := evsGitObjectOid(kind, content)
	if self.HasGitObject(oid) {
		return oid, nil
	}
	if _, err := self.writer.Add(kind, bytes.NewReader(content), int64(len(content))); err != nil {
		return EvsGitOid{}, err
	}
	self.pending[oid] = kind
	if kind != evsGitBlobKind {
		self.pendingBytes[oid] = bytes.Clone(content)
	}
	return oid, nil
}

// A blob, streamed: its oid is known only once it is read, so an object the sink holds already is taken back out of
// the pack after it is read, and a pack never holds one object twice.
func (self *EvsGitPackSink) WriteGitObjectFrom(kind string, content io.Reader, size int64) (EvsGitOid, error) {
	before := self.writer.ByteCount()
	oid, err := self.writer.Add(kind, content, size)
	if err != nil {
		return EvsGitOid{}, err
	}
	if self.HasGitObject(oid) {
		return oid, self.writer.dropLast(self.writer.ByteCount() - before)
	}
	self.pending[oid] = kind
	return oid, nil
}

// Whether oid is pending in the pack or held by the repository.
func (self *EvsGitPackSink) HasGitObject(oid EvsGitOid) bool {
	if _, ok := self.pending[oid]; ok {
		return true
	}
	return self.held != nil && self.held(oid)
}

// A pending tree, commit or tag, which the repository does not hold until the flush; a pending blob is not kept.
func (self *EvsGitPackSink) PendingGitObject(oid EvsGitOid) (string, []byte, bool) {
	content, ok := self.pendingBytes[oid]
	if !ok {
		return "", nil, false
	}
	return self.pending[oid], content, true
}

// Flushes the pack when it has reached its chunk.
func (self *EvsGitPackSink) FlushIfFull(ctx context.Context) error {
	if self.writer.ByteCount() < self.chunkByteCount {
		return nil
	}
	return self.Flush(ctx)
}

// Writes the pack through the flush function and starts the next; a flush that fails keeps every object pending.
func (self *EvsGitPackSink) Flush(ctx context.Context) error {
	if self.writer.Count() == 0 {
		return nil
	}
	reader, writer := io.Pipe()
	written := make(chan error, 1)
	go func() {
		_, err := self.writer.WriteTo(writer)
		writer.CloseWithError(err)
		written <- err
	}()
	flushErr := self.flush(ctx, reader)
	// a flush that stops reading early ends the write, which must end before the spool is cut
	reader.CloseWithError(io.ErrClosedPipe)
	writeErr := <-written
	if flushErr != nil {
		return flushErr
	}
	if writeErr != nil {
		return writeErr
	}
	self.pending = map[EvsGitOid]string{}
	self.pendingBytes = map[EvsGitOid][]byte{}
	return self.writer.Reset()
}
