// §5.9's sealed files: XChaCha20-Poly1305 over 64 KiB chunks, chosen because wasm's AES is table-based
// (D-CORE-10). Streaming, so a file never needs a second copy in memory.
//
//	magic "URSF" | version 1 | root generation, uint64 | class length, uint8 | class | nonce prefix, 16 B
//	chunk 0 | chunk 1 | ... | final chunk
//
// Integers are big endian. A chunk is its plaintext plus a 16 B tag, and every chunk but the last holds
// exactly 64 KiB. A file always has a final chunk, an empty one if its plaintext is empty. Chunk i's
// nonce is the random prefix then i as a uint64, and its additional data is the whole header, the
// file's path, i and a flag for the final chunk:
//
//	header | path length, uint32 | path | i, uint64 | final, uint8
//
// So a cut file ends on a chunk not flagged final, a reordered one has the wrong index, and a moved one
// the wrong path. The key is the file class's, from the root the header names, so a file sealed under
// another network's root or another class fails too. The format is unfrozen until M1's exit
// (D-PHASE-7), and testdata/keychain/ pins its bytes.

package sidecar

import (
	"bufio"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// The format's values.
const (
	sealMagic                = "URSF"
	sealVersion              = 1
	sealChunkByteCount       = 64 * 1024
	sealTagByteCount         = chacha20poly1305.Overhead
	sealNoncePrefixByteCount = chacha20poly1305.NonceSizeX - 8
	sealClassMaxByteCount    = 64
	// magic, version, generation and the class's length
	sealFixedHeaderByteCount = 4 + 1 + 8 + 1
)

var errSealFormat = fmt.Errorf("%w: not a sealed file", ErrSidecarStoreFailed)

// Whatever opens a chunk failed, which is all a reader ever learns about why: a wrong key, a wrong path
// and a bit flip are one answer.
var errSealOpen = fmt.Errorf("%w: a sealed chunk failed", ErrSidecarStoreFailed)

// Whether class can name a file class: a lowercase word that fits the header and is safe in an HKDF
// info string. Classes come from code, so this catches bugs rather than input.
func isSealClass(class string) bool {
	if class == "" || sealClassMaxByteCount < len(class) || class[0] == '-' {
		return false
	}
	for i := 0; i < len(class); i += 1 {
		if c := class[i]; !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// The clear part of a sealed file. Every field of it is in each chunk's additional data.
type sealHeader struct {
	// Which root of keychain.wrap seals this file.
	generation  uint64
	class       string
	noncePrefix [sealNoncePrefixByteCount]byte
}

// The header's bytes.
func (self *sealHeader) encode() []byte {
	encoded := make([]byte, 0, sealFixedHeaderByteCount+len(self.class)+sealNoncePrefixByteCount)
	encoded = append(encoded, sealMagic...)
	encoded = append(encoded, sealVersion)
	encoded = binary.BigEndian.AppendUint64(encoded, self.generation)
	encoded = append(encoded, byte(len(self.class)))
	encoded = append(encoded, self.class...)
	return append(encoded, self.noncePrefix[:]...)
}

// Reads a header from the front of in, which never takes more than a header's bound in memory.
func readSealHeader(in io.Reader) (*sealHeader, error) {
	fixed := make([]byte, sealFixedHeaderByteCount)
	if _, err := io.ReadFull(in, fixed); err != nil {
		return nil, sealReadFault(err)
	}
	if string(fixed[0:4]) != sealMagic || fixed[4] != sealVersion {
		return nil, errSealFormat
	}
	classByteCount := int(fixed[13])
	if classByteCount == 0 || sealClassMaxByteCount < classByteCount {
		return nil, errSealFormat
	}
	rest := make([]byte, classByteCount+sealNoncePrefixByteCount)
	if _, err := io.ReadFull(in, rest); err != nil {
		return nil, sealReadFault(err)
	}
	class := string(rest[:classByteCount])
	if !isSealClass(class) {
		return nil, errSealFormat
	}
	header := &sealHeader{
		generation: binary.BigEndian.Uint64(fixed[5:13]),
		class:      class,
	}
	copy(header.noncePrefix[:], rest[classByteCount:])
	return header, nil
}

// A short read inside a header is a cut file, which is a failure, and so is a medium's fault.
func sealReadFault(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return errSealFormat
	}
	return storeFault(err)
}

// Chunk i's nonce.
func sealNonce(noncePrefix *[sealNoncePrefixByteCount]byte, chunkIndex uint64) []byte {
	nonce := make([]byte, 0, chacha20poly1305.NonceSizeX)
	nonce = append(nonce, noncePrefix[:]...)
	return binary.BigEndian.AppendUint64(nonce, chunkIndex)
}

// Chunk i's additional data.
func sealAdditionalData(encodedHeader []byte, path string, chunkIndex uint64, final bool) []byte {
	additionalData := make([]byte, 0, len(encodedHeader)+4+len(path)+8+1)
	additionalData = append(additionalData, encodedHeader...)
	additionalData = binary.BigEndian.AppendUint32(additionalData, uint32(len(path)))
	additionalData = append(additionalData, path...)
	additionalData = binary.BigEndian.AppendUint64(additionalData, chunkIndex)
	if final {
		return append(additionalData, 1)
	}
	return append(additionalData, 0)
}

// Seals a stream onto out. A full chunk waits for the next byte, since only then is it known not to be
// the last. aead is asked for at each chunk, so a keychain that locks stops the stream.
type sealWriter struct {
	aead          func() (cipher.AEAD, error)
	out           io.Writer
	header        *sealHeader
	encodedHeader []byte
	path          string
	plaintext     []byte
	sealed        []byte
	chunkIndex    uint64
	finished      bool
	err           error
}

// Writes the header to out. aead answers the class's key.
func newSealWriter(out io.Writer, header *sealHeader, path string, aead func() (cipher.AEAD, error)) (*sealWriter, error) {
	encodedHeader := header.encode()
	if _, err := out.Write(encodedHeader); err != nil {
		return nil, err
	}
	return &sealWriter{
		aead:          aead,
		out:           out,
		header:        header,
		encodedHeader: encodedHeader,
		path:          path,
		plaintext:     make([]byte, 0, sealChunkByteCount),
		sealed:        make([]byte, 0, sealChunkByteCount+sealTagByteCount),
	}, nil
}

// Seals the buffered plaintext as the next chunk.
func (self *sealWriter) flushChunk(final bool) error {
	aead, err := self.aead()
	if err != nil {
		return err
	}
	additionalData := sealAdditionalData(self.encodedHeader, self.path, self.chunkIndex, final)
	nonce := sealNonce(&self.header.noncePrefix, self.chunkIndex)
	self.sealed = aead.Seal(self.sealed[:0], nonce, self.plaintext, additionalData)
	if _, err := self.out.Write(self.sealed); err != nil {
		return err
	}
	clear(self.plaintext)
	self.plaintext = self.plaintext[:0]
	self.chunkIndex += 1
	return nil
}

// Takes p, sealing every chunk this fills but the last.
func (self *sealWriter) Write(p []byte) (int, error) {
	if self.err != nil {
		return 0, self.err
	}
	if self.finished {
		return 0, ErrSidecarStoreFailed
	}
	written := 0
	for 0 < len(p) {
		if len(self.plaintext) == sealChunkByteCount {
			if err := self.flushChunk(false); err != nil {
				self.err = err
				return written, err
			}
		}
		taken := min(len(p), sealChunkByteCount-len(self.plaintext))
		self.plaintext = append(self.plaintext, p[:taken]...)
		p = p[taken:]
		written += taken
	}
	return written, nil
}

// Seals the final chunk. Nothing more may be written.
func (self *sealWriter) finish() error {
	if self.err != nil {
		return self.err
	}
	if self.finished {
		return nil
	}
	self.finished = true
	if err := self.flushChunk(true); err != nil {
		self.err = err
		return err
	}
	return nil
}

// Drops what is buffered, for a writer that will never finish.
func (self *sealWriter) abandon() {
	self.finished = true
	clear(self.plaintext[:cap(self.plaintext)])
	self.plaintext = self.plaintext[:0]
}

// Reads a sealed stream past its header. No plaintext leaves here until its chunk has authenticated,
// and io.EOF comes only after a chunk flagged final did. aead is asked for at each chunk, so a keychain
// that locks stops the stream.
type sealReader struct {
	aead          func() (cipher.AEAD, error)
	in            *bufio.Reader
	header        *sealHeader
	encodedHeader []byte
	path          string
	sealed        []byte
	plaintext     []byte
	unread        []byte
	chunkIndex    uint64
	finished      bool
	err           error
}

// in follows the header that was read from it.
func newSealReader(in io.Reader, header *sealHeader, path string, aead func() (cipher.AEAD, error)) *sealReader {
	return &sealReader{
		aead:          aead,
		in:            bufio.NewReader(in),
		header:        header,
		encodedHeader: header.encode(),
		path:          path,
		sealed:        make([]byte, sealChunkByteCount+sealTagByteCount),
		plaintext:     make([]byte, 0, sealChunkByteCount),
	}
}

// Opens the next chunk. It is the final one exactly when nothing follows it, and its additional data
// holds the writer to having said so.
func (self *sealReader) nextChunk() error {
	byteCount, err := io.ReadFull(self.in, self.sealed)
	final := false
	switch {
	case err == nil:
		if _, peekErr := self.in.Peek(1); peekErr == io.EOF {
			final = true
		} else if peekErr != nil {
			return storeFault(peekErr)
		}
	case err == io.EOF || err == io.ErrUnexpectedEOF:
		final = true
		if byteCount < sealTagByteCount {
			return errSealOpen
		}
	default:
		return storeFault(err)
	}
	aead, err := self.aead()
	if err != nil {
		return err
	}
	additionalData := sealAdditionalData(self.encodedHeader, self.path, self.chunkIndex, final)
	nonce := sealNonce(&self.header.noncePrefix, self.chunkIndex)
	plaintext, err := aead.Open(self.plaintext[:0], nonce, self.sealed[:byteCount], additionalData)
	if err != nil {
		return errSealOpen
	}
	self.unread = plaintext
	self.chunkIndex += 1
	self.finished = final
	return nil
}

// Hands out authenticated plaintext, and a sticky error once one comes.
func (self *sealReader) Read(p []byte) (int, error) {
	for len(self.unread) == 0 {
		if self.err != nil {
			return 0, self.err
		}
		if self.finished {
			self.err = io.EOF
			return 0, io.EOF
		}
		if err := self.nextChunk(); err != nil {
			self.err = err
			return 0, err
		}
	}
	read := copy(p, self.unread)
	self.unread = self.unread[read:]
	return read, nil
}
