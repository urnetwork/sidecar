// The VPN component's sealed store (DESIGN-DETAILS 4.2.2): every record of an inner PostureStore sealed under the
// component's forwarding root key, so what sits in its container, and any copy of it, opens only to the component.
//
//	record  "UFS1" || file id (16 random bytes, new at each write) || chunks
//	chunk   AES-256-GCM of up to 64 KiB of plaintext, under HKDF-SHA256(root key, salt file id,
//	        info "urnetwork-sidecar-v1/forward-store" || name), nonce u32be(0) || u64be(chunk index),
//	        AAD name || file id || u64be(chunk index) || u8(final)
//
// A record's last chunk is sealed final: its plaintext's last 64 KiB or less, or an empty chunk for an empty record. So
// a record cut at a chunk boundary leaves a last chunk sealed as not final, which fails, as does a byte flipped,
// chunks swapped or reordered, bytes after the final chunk, or a record moved under another name, whose key and AAD
// are another's. A fresh file id gives each write its own key, which makes the counter nonce safe.
//
// A record streams, so rows of 4 MiB never sit whole in memory: a read returns each chunk once its tag verifies, and
// ends only once the final chunk has verified, so a reader that reads to the end has read exactly what was sealed,
// and every posture read does. A chunk that fails is ErrPostureStoreFailed, never Absent, so a tampered store is
// pending, never legacy.
//
// AES-GCM and HKDF are the standard library's, since this package imports nothing beyond std, connect and
// protocol/bridge (§4.4). Safe for concurrent use, as its inner store is.

package device

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// The sealed record's format values (DESIGN-DETAILS 4.2.2).
const (
	sealedPostureMagic            = "UFS1"
	sealedPostureFileIdByteCount  = 16
	sealedPostureRootKeyByteCount = 32
	// AES-256's
	sealedPostureRecordKeyByteCount = 32
	sealedPostureChunkByteCount     = 64 * 1024
	sealedPostureInfo               = "urnetwork-sidecar-v1/forward-store"
	sealedPostureTagByteCount       = 16
	sealedPostureNonceByteCount     = 12
)

// A store that seals every record of inner (the file's comment).
type sealedPostureStore struct {
	inner   PostureStore
	rootKey []byte
}

// Wraps inner so every record is sealed under rootKey, the component's forwarding root key, 32 bytes, which the
// platform's key store holds (fwd.<net8>.root, SDK-M8-16). The key is copied, so the caller may zero its own.
func NewSealedPostureStore(inner PostureStore, rootKey []byte) (PostureStore, error) {
	if inner == nil {
		return nil, fmt.Errorf("%w: no inner store", ErrPostureStoreFailed)
	}
	if len(rootKey) != sealedPostureRootKeyByteCount {
		return nil, fmt.Errorf("%w: a root key of %d bytes", ErrPostureStoreFailed, len(rootKey))
	}
	key := bytes.Clone(rootKey)
	testHookSecret("forward_store_root_key", key)
	return &sealedPostureStore{inner: inner, rootKey: key}, nil
}

// The AEAD of a record named name under file id fileId.
func (self *sealedPostureStore) recordAead(name string, fileId []byte) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, self.rootKey, fileId, sealedPostureInfo+name, sealedPostureRecordKeyByteCount)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPostureStoreFailed, err)
	}
	testHookSecret("forward_store_record_key", key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPostureStoreFailed, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrPostureStoreFailed, err)
	}
	return aead, nil
}

// A chunk's nonce: u32be(0) || u64be(index).
func sealedPostureNonce(index uint64) []byte {
	nonce := make([]byte, sealedPostureNonceByteCount)
	binary.BigEndian.PutUint64(nonce[4:], index)
	return nonce
}

// A chunk's AAD: name || file id || u64be(index) || u8(final).
func sealedPostureAad(name string, fileId []byte, index uint64, final bool) []byte {
	aad := make([]byte, 0, len(name)+len(fileId)+9)
	aad = append(aad, name...)
	aad = append(aad, fileId...)
	aad = binary.BigEndian.AppendUint64(aad, index)
	if final {
		return append(aad, 1)
	}
	return append(aad, 0)
}

// Streams the record, opening each chunk as it is read. Absent passes through as it is.
func (self *sealedPostureStore) Open(name string) (io.ReadCloser, error) {
	source, err := self.inner.Open(name)
	if err != nil {
		return nil, err
	}
	buffered := bufio.NewReaderSize(source, sealedPostureChunkByteCount+sealedPostureTagByteCount+1)
	header := make([]byte, len(sealedPostureMagic)+sealedPostureFileIdByteCount)
	if _, err := io.ReadFull(buffered, header); err != nil {
		source.Close()
		return nil, fmt.Errorf("%w: a sealed record cut inside its header", ErrPostureStoreFailed)
	}
	if string(header[:len(sealedPostureMagic)]) != sealedPostureMagic {
		source.Close()
		return nil, fmt.Errorf("%w: a record that is not sealed", ErrPostureStoreFailed)
	}
	fileId := header[len(sealedPostureMagic):]
	aead, err := self.recordAead(name, fileId)
	if err != nil {
		source.Close()
		return nil, err
	}
	return &sealedPostureReader{
		source:     source,
		buffered:   buffered,
		aead:       aead,
		name:       name,
		fileId:     fileId,
		ciphertext: make([]byte, sealedPostureChunkByteCount+sealedPostureTagByteCount),
	}, nil
}

// Seals what write writes into one inner write, so the inner store's durability holds whole.
func (self *sealedPostureStore) Write(name string, write func(writer io.Writer) error) error {
	fileId := make([]byte, sealedPostureFileIdByteCount)
	if _, err := rand.Read(fileId); err != nil {
		return fmt.Errorf("%w: %v", ErrPostureStoreFailed, err)
	}
	aead, err := self.recordAead(name, fileId)
	if err != nil {
		return err
	}
	return self.inner.Write(name, func(writer io.Writer) error {
		if _, err := writer.Write(append([]byte(sealedPostureMagic), fileId...)); err != nil {
			return err
		}
		sealer := &sealedPostureWriter{
			writer: writer,
			aead:   aead,
			name:   name,
			fileId: fileId,
			buffer: make([]byte, 0, sealedPostureChunkByteCount),
		}
		if err := write(sealer); err != nil {
			return err
		}
		return sealer.seal(true)
	})
}

// The inner store's.
func (self *sealedPostureStore) Remove(name string) error {
	return self.inner.Remove(name)
}

// The inner store's.
func (self *sealedPostureStore) List() ([]string, error) {
	return self.inner.List()
}

// Buffers a chunk's plaintext and seals it once the next byte shows it is not the last, or at the end as final.
type sealedPostureWriter struct {
	writer io.Writer
	aead   cipher.AEAD
	name   string
	fileId []byte
	index  uint64
	buffer []byte
}

// Takes p, sealing each full chunk once more follows it.
func (self *sealedPostureWriter) Write(p []byte) (int, error) {
	written := 0
	for 0 < len(p) {
		if len(self.buffer) == sealedPostureChunkByteCount {
			if err := self.seal(false); err != nil {
				return written, err
			}
		}
		n := copy(self.buffer[len(self.buffer):sealedPostureChunkByteCount], p)
		self.buffer = self.buffer[:len(self.buffer)+n]
		p = p[n:]
		written += n
	}
	return written, nil
}

// Seals the buffered chunk and writes it.
func (self *sealedPostureWriter) seal(final bool) error {
	sealed := self.aead.Seal(nil, sealedPostureNonce(self.index), self.buffer,
		sealedPostureAad(self.name, self.fileId, self.index, final))
	if _, err := self.writer.Write(sealed); err != nil {
		return err
	}
	self.index += 1
	self.buffer = self.buffer[:0]
	return nil
}

// Opens a record's chunks in order, returning each one's plaintext only once its tag verified, and its end only once
// the final chunk did.
type sealedPostureReader struct {
	source     io.ReadCloser
	buffered   *bufio.Reader
	aead       cipher.AEAD
	name       string
	fileId     []byte
	index      uint64
	ciphertext []byte
	// what is left of the chunk last opened
	plaintext []byte
	done      bool
	err       error
}

// The next bytes of the record. A chunk that does not open is ErrPostureStoreFailed, and stays so.
func (self *sealedPostureReader) Read(p []byte) (int, error) {
	for len(self.plaintext) == 0 {
		if self.err != nil {
			return 0, self.err
		}
		if self.done {
			return 0, io.EOF
		}
		self.err = self.openNext()
	}
	n := copy(p, self.plaintext)
	self.plaintext = self.plaintext[n:]
	return n, nil
}

// Reads and opens the next chunk: a short one, or a full one with nothing after it, is the final.
func (self *sealedPostureReader) openNext() error {
	n, err := io.ReadFull(self.buffered, self.ciphertext)
	final := false
	switch {
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		final = true
	case err != nil:
		return postureStoreFault(err)
	default:
		if _, err := self.buffered.Peek(1); errors.Is(err, io.EOF) {
			final = true
		} else if err != nil {
			return postureStoreFault(err)
		}
	}
	if n < sealedPostureTagByteCount {
		return fmt.Errorf("%w: a sealed record cut short", ErrPostureStoreFailed)
	}
	plaintext, err := self.aead.Open(self.ciphertext[:0], sealedPostureNonce(self.index), self.ciphertext[:n],
		sealedPostureAad(self.name, self.fileId, self.index, final))
	if err != nil {
		return fmt.Errorf("%w: a sealed chunk that does not open", ErrPostureStoreFailed)
	}
	self.plaintext = plaintext
	self.index += 1
	self.done = final
	return nil
}

// Closes the inner record.
func (self *sealedPostureReader) Close() error {
	return self.source.Close()
}
