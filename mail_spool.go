//go:build !sidecar_http && !ios_extension

// §15.5's spool (D-MAIL-5, R-MAIL-13, QD-196, QD-641; MAIL-M7-14): where a receiver keeps one message from its first
// byte until every deposit of it committed. A message streams in as DATA or BDAT deliver it, in chunks of
// ChunkByteCount, and each full chunk goes to the mail component's store at once, sealed under a random key this
// message alone has and only memory holds, so the receiver holds one chunk of any message whatever its size, the
// sender's 50 MiB included, and a crash leaves bytes no one can open, which the next start sweeps (sweepMailSpools).
//
//	seal    XChaCha20-Poly1305 per chunk, the nonce the chunk's index and the associated data the index and whether
//	        it is the last, so a chunk read at another index, a dropped tail or a chunk put after the last does not
//	        open; the store seals each file again under its own key (§5.9)
//	hash    message_sha256 is taken as the bytes arrive, over the message as received, before anything is added
//	read    ReadAt opens the chunks a read spans, one at a time, into a buffer of its own, for mox's dkim.Verify, ARC
//	        and the header view, which read the message at offsets, and for each repo's deposit, which replays it
//	        from the start: several readers at once, never a whole message in memory
//
// Writes come from the session's goroutine alone, and reads only after finish, from any goroutine. The key reaches
// testHookSecret where it is made and nowhere else: no log, no store file and no server sees it.

package sidecar

import (
	"crypto/cipher"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// The mail component's store directory a message's sealed chunks go under, one directory a message.
const mailSpoolDirectory = "spool/"

var (
	// The spool was written to after finish, read before it, or used after close.
	errMailSpoolState = errors.New("mail spool: used out of order")
	// A chunk did not open under the message's key: the store returned another chunk, or a damaged one.
	errMailSpoolChunk = errors.New("mail spool: a chunk does not open")
)

// One message's spool. See the file header.
type mailSpool struct {
	store          SidecarStore
	name           string
	chunkByteCount int
	aead           cipher.AEAD
	hash           hash.Hash

	// the session's: the chunk being filled, the chunks sealed and the bytes taken
	buffer     []byte
	chunkCount int
	size       int64
	finished   bool
	sha256     [sha256.Size]byte

	stateLock sync.Mutex
	closed    bool
	// the most plaintext bytes in memory at once, the chunk being filled and each read's open chunk: the working
	// set a test holds to its bound
	heldByteCount     int64
	peakHeldByteCount int64
}

// An empty spool under store's spool directory, its key drawn now. chunkByteCount must be positive.
func newMailSpool(store SidecarStore, chunkByteCount int) (*mailSpool, error) {
	if store == nil || chunkByteCount <= 0 {
		return nil, fmt.Errorf("%w: no store or no chunk size", errMailSpoolState)
	}
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := cryptorand.Read(key); err != nil {
		return nil, fmt.Errorf("mail spool: no randomness for a key: %w", err)
	}
	testHookSecret("mail_spool_key", key)
	aead, err := chacha20poly1305.NewX(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	nameBytes := make([]byte, 16)
	if _, err := cryptorand.Read(nameBytes); err != nil {
		return nil, fmt.Errorf("mail spool: no randomness for a name: %w", err)
	}
	return &mailSpool{
		store:          store,
		name:           mailSpoolDirectory + hex.EncodeToString(nameBytes),
		chunkByteCount: chunkByteCount,
		aead:           aead,
		hash:           sha256.New(),
		buffer:         make([]byte, 0, chunkByteCount),
	}, nil
}

// Counts byteCount more plaintext bytes in memory, a negative count releasing them.
func (self *mailSpool) hold(byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.heldByteCount += byteCount
	self.peakHeldByteCount = max(self.peakHeldByteCount, self.heldByteCount)
}

// The chunk file of index.
func (self *mailSpool) chunkName(index int) string {
	return fmt.Sprintf("%s/%08d", self.name, index)
}

// The nonce and associated data of chunk index, last saying whether it ends the message.
func (self *mailSpool) chunkNonceAndData(index int, last bool) ([]byte, []byte) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	binary.BigEndian.PutUint64(nonce[len(nonce)-8:], uint64(index))
	data := binary.BigEndian.AppendUint64(nil, uint64(index))
	if last {
		data = append(data, 1)
	} else {
		data = append(data, 0)
	}
	return nonce, data
}

// Takes p into the message: hashed, and each full chunk sealed to the store. The session's goroutine alone.
func (self *mailSpool) Write(p []byte) (int, error) {
	if self.finished || self.isClosed() {
		return 0, errMailSpoolState
	}
	self.hash.Write(p)
	written := 0
	for written < len(p) {
		take := min(len(p)-written, self.chunkByteCount-len(self.buffer))
		if len(self.buffer) == 0 && 0 < take {
			self.hold(int64(self.chunkByteCount))
		}
		self.buffer = append(self.buffer, p[written:written+take]...)
		written += take
		self.size += int64(take)
		if len(self.buffer) == self.chunkByteCount {
			if err := self.sealChunk(false); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

// Seals the buffered bytes as the next chunk.
func (self *mailSpool) sealChunk(last bool) error {
	nonce, data := self.chunkNonceAndData(self.chunkCount, last)
	sealed := self.aead.Seal(nil, nonce, self.buffer, data)
	writer, err := self.store.Create(self.chunkName(self.chunkCount))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(sealed); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.chunkCount += 1
	if 0 < len(self.buffer) || last {
		self.hold(-int64(self.chunkByteCount))
	}
	clear(self.buffer)
	self.buffer = self.buffer[:0]
	return nil
}

// Ends the message at its last byte: the tail sealed as the last chunk, an empty one for a message that ended on a
// chunk's edge, and the hash fixed. Reads may start after.
func (self *mailSpool) finish() error {
	if self.finished || self.isClosed() {
		return errMailSpoolState
	}
	if len(self.buffer) == 0 {
		// the last chunk is marked even when it is empty, so a dropped tail never reads as the end
		self.hold(int64(self.chunkByteCount))
	}
	if err := self.sealChunk(true); err != nil {
		return err
	}
	self.finished = true
	self.buffer = nil
	copy(self.sha256[:], self.hash.Sum(nil))
	return nil
}

// The message's bytes so far.
func (self *mailSpool) Size() int64 {
	return self.size
}

// SHA-256 of the message as received, once finished.
func (self *mailSpool) Sha256() [sha256.Size]byte {
	return self.sha256
}

// Whether close ran.
func (self *mailSpool) isClosed() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.closed
}

// Reads at off, once finished: each chunk the read spans opened into a buffer of its own. Safe for concurrent use.
func (self *mailSpool) ReadAt(p []byte, off int64) (int, error) {
	if !self.finished || self.isClosed() {
		return 0, errMailSpoolState
	}
	if off < 0 {
		return 0, fmt.Errorf("%w: a negative offset", errMailSpoolState)
	}
	if self.size <= off {
		return 0, io.EOF
	}
	read := 0
	for read < len(p) && off+int64(read) < self.size {
		at := off + int64(read)
		index := int(at / int64(self.chunkByteCount))
		chunk, err := self.openChunk(index)
		if err != nil {
			return read, err
		}
		read += copy(p[read:], chunk[at%int64(self.chunkByteCount):])
		clear(chunk)
		self.hold(-int64(self.chunkByteCount))
	}
	if read < len(p) {
		return read, io.EOF
	}
	return read, nil
}

// Chunk index's plaintext, counted in what the spool holds until the caller releases it.
func (self *mailSpool) openChunk(index int) ([]byte, error) {
	reader, err := self.store.Open(self.chunkName(index))
	if err != nil {
		return nil, err
	}
	sealed, err := io.ReadAll(io.LimitReader(reader, int64(self.chunkByteCount+self.aead.Overhead()+1)))
	reader.Close()
	if err != nil {
		return nil, err
	}
	nonce, data := self.chunkNonceAndData(index, index == self.chunkCount-1)
	self.hold(int64(self.chunkByteCount))
	chunk, err := self.aead.Open(nil, nonce, sealed, data)
	if err != nil {
		self.hold(-int64(self.chunkByteCount))
		return nil, errMailSpoolChunk
	}
	return chunk, nil
}

// The whole message from its start, a reader of its own, which the deposits replay: it keeps the chunk it is in open
// until it has read past it, so a replay opens each chunk once.
func (self *mailSpool) Reader() io.Reader {
	return &mailSpoolReader{spool: self, index: -1}
}

// A reader of a finished spool from its start. Not safe for concurrent use; each replay takes its own.
type mailSpoolReader struct {
	spool  *mailSpool
	offset int64
	// the open chunk, and its index, -1 for none
	index int
	chunk []byte
}

// The next bytes of the message, io.EOF past its end; the open chunk goes once the read passes it.
func (self *mailSpoolReader) Read(p []byte) (int, error) {
	spool := self.spool
	if !spool.finished || spool.isClosed() {
		self.release()
		return 0, errMailSpoolState
	}
	if spool.size <= self.offset {
		self.release()
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}
	index := int(self.offset / int64(spool.chunkByteCount))
	if index != self.index {
		self.release()
		chunk, err := spool.openChunk(index)
		if err != nil {
			return 0, err
		}
		self.index, self.chunk = index, chunk
	}
	n := copy(p, self.chunk[self.offset%int64(spool.chunkByteCount):])
	self.offset += int64(n)
	return n, nil
}

// Lets the open chunk go.
func (self *mailSpoolReader) release() {
	if self.chunk == nil {
		return
	}
	clear(self.chunk)
	self.chunk = nil
	self.index = -1
	self.spool.hold(-int64(self.spool.chunkByteCount))
}

// Drops the message: every chunk file removed and the key forgotten. A second close does nothing.
func (self *mailSpool) close() {
	first := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return false
		}
		self.closed = true
		return true
	}()
	if !first {
		return
	}
	clear(self.buffer)
	self.buffer = nil
	count := self.chunkCount
	if !self.finished {
		// a chunk whose seal was cut short may be there past the count
		count += 1
	}
	for index := range count {
		self.store.Remove(self.chunkName(index))
	}
}

// The most plaintext bytes the spool held in memory at once.
func (self *mailSpool) peakHeld() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.peakHeldByteCount
}

// Removes every chunk a spool left in store: what a crash left, sealed under keys no one holds. A receiver calls it
// before it takes its first message.
func sweepMailSpools(store SidecarStore) error {
	if store == nil {
		return nil
	}
	entries, err := store.List(mailSpoolDirectory)
	if err != nil {
		return err
	}
	var firstErr error
	for _, entry := range entries {
		if err := store.Remove(entry.Name); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
