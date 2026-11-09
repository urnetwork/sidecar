// §5.9's append-only sealed records, which §16.6's ledger and other journals need: "append-only, each record
// fsynced before the step it guards". A sealed file (state_seal.go) is swapped in whole and cannot grow, so a log is
// its own format, under the same root and file class keys:
//
//	magic "URSL" | version 1 | root generation, uint64 | class length, uint8 | class
//	record 0 | record 1 | ...
//	record:  length, uint32 | the length's complement, uint32 | nonce, 24 B | XChaCha20-Poly1305 ciphertext and tag
//
// Integers are big endian, and a length counts the nonce, the ciphertext and the tag. Record i's additional data
// is the header, the file's path, i and the SHA-256 of record i-1's bytes as stored, frame included, or 32 zero
// bytes for record 0:
//
//	header | path length, uint32 | path | i, uint64 | previous, 32 B
//
// So a record moved to another file, another index or after another record fails, and so does one dropped from
// the middle, since the record after it names what it followed. Each record draws its own random nonce, never one
// from its index, because a torn record's index is written again by the next append.
//
// An append writes one record and fsyncs before it returns, and a new file's directory after that. A kill can
// leave only the last record short, so a reader takes a tail that ends inside a frame, inside a record whose
// frame says it runs past the end, or in zero bytes the medium never wrote, as a write that never finished: it
// ends the log, and the next append cuts it off. Anything else that fails, a frame whose complement disagrees or
// a whole record whose tag fails, is ErrSidecarStoreFailed, never the end of the log (D-CORE-15), because a guard
// may already have run on it.
//
// A rotation moves a log to the new root as it moves a sealed file: copied record by record under fresh nonces
// and a fresh chain, and swapped in only if no append landed since the copy (resealLog). The format is unfrozen
// until M3's exit.

package sidecar

import (
	"bufio"
	"bytes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

// The format's values.
const (
	storeLogMagic   = "URSL"
	storeLogVersion = 1
	// magic, version, generation and the class's length
	storeLogFixedHeaderByteCount = 4 + 1 + 8 + 1
	// a record's length and its complement
	storeLogFrameByteCount = 8
	storeLogNonceByteCount = chacha20poly1305.NonceSizeX
	// the least a record holds: its nonce and an empty plaintext's tag
	storeLogSealedMinByteCount = storeLogNonceByteCount + chacha20poly1305.Overhead
	// The most one record's plaintext holds. It bounds what a reader takes into memory for one record, which
	// every host must fit, so it is a format bound, as keychain.ur's is, not a tunable.
	StoreLogRecordMaxByteCount = 16 * 1024 * 1024
)

var (
	// A store that keeps no logs: one a test built for files alone. Every store an instance hands out keeps them.
	ErrSidecarStoreNoLog = errors.New("store keeps no logs")
	// The bytes are not a log, or a frame is damaged where no torn write leaves damage.
	errStoreLogFormat = fmt.Errorf("%w: not a sealed log", ErrSidecarStoreFailed)
	// A whole record failed: a wrong key, a wrong path, a record moved or dropped before it, or a bit flip.
	errStoreLogOpen = fmt.Errorf("%w: a sealed log record failed", ErrSidecarStoreFailed)
	// The file is shorter than an append last left it, which nothing here does.
	errStoreLogShrank = fmt.Errorf("%w: a sealed log lost bytes", ErrSidecarStoreFailed)
	// A record past StoreLogRecordMaxByteCount, refused before anything is written.
	ErrStoreLogRecordTooLarge = errors.New("log record too large")
)

// An append-only file of sealed records in a SidecarStore (§5.9): each record its own XChaCha20-Poly1305 unit,
// chained to the one before it, so a record is never rewritten, reordered or dropped from the middle unseen. A
// log opens only at its own path and under its own class, as a sealed file does. Calls answer
// ErrSidecarStoreLocked while the keychain is locked. Safe for concurrent use: appends to one path go one at a
// time, in this process and across every SidecarStoreLog naming it.
type SidecarStoreLog interface {
	// Seals record as the log's next and returns once it is fsynced, with, for a new file, its directory: a step
	// the record guards may run once this returns nil. After an error the record may or may not be there, as
	// after a kill, so a guard that must never run twice takes it as there.
	Append(record []byte) error
	// Calls visit with each record in order, its index from 0 and a copy it may keep, until visit answers an
	// error, which Read returns. A torn tail ends the log. A record that fails is ErrSidecarStoreFailed, so a
	// caller keeps nothing from a Read that did not return nil. ErrSidecarStoreAbsent when no file is there.
	Read(visit func(index uint64, record []byte) error) error
}

// A SidecarStore that keeps logs, as every store SidecarInstance.Store answers, and its directories, does.
// sidecartest's FakeStore keeps them too, unsealed.
type SidecarStoreLogs interface {
	// name as an append-only log of the store's class. Remove takes it away as it does a file. Nothing is created
	// until the first append.
	Log(name string) (SidecarStoreLog, error)
}

// name in store as an append-only log of sealed records (§5.9), for a journal whose records each guard a step.
// ErrSidecarStoreNoLog for a store that keeps none.
func OpenSidecarStoreLog(store SidecarStore, name string) (SidecarStoreLog, error) {
	logs, ok := store.(SidecarStoreLogs)
	if !ok {
		return nil, ErrSidecarStoreNoLog
	}
	return logs.Log(name)
}

// The clear part of a log, in every record's additional data.
type storeLogHeader struct {
	generation uint64
	class      string
}

// The header's bytes.
func (self *storeLogHeader) encode() []byte {
	encoded := make([]byte, 0, storeLogFixedHeaderByteCount+len(self.class))
	encoded = append(encoded, storeLogMagic...)
	encoded = append(encoded, storeLogVersion)
	encoded = binary.BigEndian.AppendUint64(encoded, self.generation)
	encoded = append(encoded, byte(len(self.class)))
	return append(encoded, self.class...)
}

// Whether a file starting with prefix is a log rather than a sealed file.
func isStoreLog(prefix []byte) bool {
	return bytes.Equal(prefix, []byte(storeLogMagic))
}

// Reads a header from the front of in. torn reports a file that ends before a whole header, or whose bytes are all
// zero, which only a first append a kill cut short leaves: it holds no record.
func readStoreLogHeader(in *bufio.Reader) (header *storeLogHeader, torn bool, err error) {
	fixed := make([]byte, storeLogFixedHeaderByteCount)
	n, err := io.ReadFull(in, fixed)
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return nil, true, nil
	}
	if err != nil {
		return nil, false, storeFault(err)
	}
	if string(fixed[0:4]) != storeLogMagic || fixed[4] != storeLogVersion {
		zero, err := zeroTail(fixed[:n], in)
		if err != nil {
			return nil, false, err
		}
		if zero {
			return nil, true, nil
		}
		return nil, false, errStoreLogFormat
	}
	classByteCount := int(fixed[13])
	if classByteCount == 0 || sealClassMaxByteCount < classByteCount {
		return nil, false, errStoreLogFormat
	}
	class := make([]byte, classByteCount)
	if _, err := io.ReadFull(in, class); err == io.EOF || err == io.ErrUnexpectedEOF {
		return nil, true, nil
	} else if err != nil {
		return nil, false, storeFault(err)
	}
	if !isSealClass(string(class)) {
		return nil, false, errStoreLogFormat
	}
	return &storeLogHeader{generation: binary.BigEndian.Uint64(fixed[5:13]), class: string(class)}, false, nil
}

// Whether read and everything left in in are zero bytes, which is how some media show a length they extended and
// never wrote. It reads in to its end.
func zeroTail(read []byte, in io.Reader) (bool, error) {
	for _, b := range read {
		if b != 0 {
			return false, nil
		}
	}
	buffer := make([]byte, 32*1024)
	for {
		n, err := in.Read(buffer)
		for _, b := range buffer[:n] {
			if b != 0 {
				return false, nil
			}
		}
		if err == io.EOF {
			return true, nil
		}
		if err != nil {
			return false, storeFault(err)
		}
	}
}

// Record index's additional data.
func storeLogAdditionalData(encodedHeader []byte, path string, index uint64, previous *[sha256.Size]byte) []byte {
	additionalData := make([]byte, 0, len(encodedHeader)+4+len(path)+8+sha256.Size)
	additionalData = append(additionalData, encodedHeader...)
	additionalData = binary.BigEndian.AppendUint32(additionalData, uint32(len(path)))
	additionalData = append(additionalData, path...)
	additionalData = binary.BigEndian.AppendUint64(additionalData, index)
	return append(additionalData, previous[:]...)
}

// A record's frame: its sealed length and that length's complement.
func storeLogFrame(sealedByteCount int) []byte {
	frame := make([]byte, 0, storeLogFrameByteCount)
	frame = binary.BigEndian.AppendUint32(frame, uint32(sealedByteCount))
	return binary.BigEndian.AppendUint32(frame, ^uint32(sealedByteCount))
}

// What a reader chains: SHA-256 over a record as stored, frame and all.
func storeLogRecordHash(frame []byte, sealed []byte) [sha256.Size]byte {
	hash := sha256.New()
	hash.Write(frame)
	hash.Write(sealed)
	var sum [sha256.Size]byte
	hash.Sum(sum[:0])
	return sum
}

// Where a log ends: what its last append left, or a read found. Holds no secret: the hash is of ciphertext.
type storeLogTail struct {
	// Through the last whole record: what a torn tail is cut back to. 0 for a file holding no whole header.
	byteCount int64
	// Whole records.
	recordCount uint64
	// SHA-256 of the last record as stored, zero before the first.
	previous [sha256.Size]byte
	// The header's bytes, nil while the file holds none whole.
	encodedHeader []byte
	generation    uint64
}

// Reads the log in at path: its header, then each record, opened with aead for the header's generation and handed
// to visit when visit is not nil. Answers where the log ends, whatever follows being a torn write. hold takes the
// generation's root for the read, answering its AEAD and the release.
func readStoreLog(in io.Reader, class string, path string,
	hold func(generation uint64) (cipher.AEAD, func(), error),
	visit func(index uint64, record []byte) error) (*storeLogTail, error) {
	reader := bufio.NewReader(in)
	header, torn, err := readStoreLogHeader(reader)
	if err != nil {
		return nil, err
	}
	if torn {
		return &storeLogTail{}, nil
	}
	if header.class != class {
		return nil, errStoreLogOpen
	}
	tail := &storeLogTail{encodedHeader: header.encode(), generation: header.generation}
	tail.byteCount = int64(len(tail.encodedHeader))
	// taken at the first whole record, so a log holding none needs no root
	var aead cipher.AEAD
	frame := make([]byte, storeLogFrameByteCount)
	for {
		n, err := io.ReadFull(reader, frame)
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			// nothing more, or a frame a kill cut short
			return tail, nil
		}
		if err != nil {
			return nil, storeFault(err)
		}
		sealedByteCount := binary.BigEndian.Uint32(frame[0:4])
		if ^sealedByteCount != binary.BigEndian.Uint32(frame[4:8]) || sealedByteCount < storeLogSealedMinByteCount ||
			storeLogSealedMinByteCount+StoreLogRecordMaxByteCount < sealedByteCount {
			zero, err := zeroTail(frame[:n], reader)
			if err != nil {
				return nil, err
			}
			if zero {
				return tail, nil
			}
			return nil, errStoreLogFormat
		}
		// grows as bytes arrive, so a frame claiming more than the file holds allocates no more than the file
		sealed, err := io.ReadAll(io.LimitReader(reader, int64(sealedByteCount)))
		if err != nil {
			return nil, storeFault(err)
		}
		if len(sealed) < int(sealedByteCount) {
			// a record whose frame says it runs past the end: a write a kill cut short
			return tail, nil
		}
		if aead == nil {
			var release func()
			aead, release, err = hold(header.generation)
			if err != nil {
				return nil, err
			}
			// runs once: aead is set from here on
			defer release()
		}
		additionalData := storeLogAdditionalData(tail.encodedHeader, path, tail.recordCount, &tail.previous)
		record, err := aead.Open(nil, sealed[:storeLogNonceByteCount], sealed[storeLogNonceByteCount:], additionalData)
		if err != nil {
			return nil, errStoreLogOpen
		}
		if visit != nil {
			if err := visit(tail.recordCount, record); err != nil {
				return nil, err
			}
		}
		tail.previous = storeLogRecordHash(frame, sealed)
		tail.recordCount += 1
		tail.byteCount += int64(storeLogFrameByteCount) + int64(sealedByteCount)
	}
}

// The logs one keychain appends to: a lock per path, held across an append's write and fsync, and each path's
// tail as its last append left it, so an append reads the file only the first time. Safe for concurrent use.
type storeLogPaths struct {
	stateLock  sync.Mutex
	pathStates map[string]*storeLogPathState
}

// One path's appends.
type storeLogPathState struct {
	appendLock sync.Mutex
	// guarded by storeLogPaths.stateLock; nil until an append has read the file, and after anything that may have
	// changed it
	tail *storeLogTail
}

// path's state, made on first use. Paths are few: one per open approval, journal or spool segment.
func (self *storeLogPaths) path(path string) *storeLogPathState {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.pathStates == nil {
		self.pathStates = map[string]*storeLogPathState{}
	}
	pathState, ok := self.pathStates[path]
	if !ok {
		pathState = &storeLogPathState{}
		self.pathStates[path] = pathState
	}
	return pathState
}

// A copy of path's tail, or nil.
func (self *storeLogPaths) tail(pathState *storeLogPathState) *storeLogTail {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if pathState.tail == nil {
		return nil
	}
	tail := *pathState.tail
	return &tail
}

// Keeps tail as path's, nil forgetting it.
func (self *storeLogPaths) setTail(pathState *storeLogPathState, tail *storeLogTail) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	pathState.tail = tail
}

// Forgets path's tail, for a rotation that swapped the file.
func (self *storeLogPaths) forget(path string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if pathState, ok := self.pathStates[path]; ok {
		pathState.tail = nil
	}
}

// The SidecarStoreLog of a sealedStore. Like the store it holds no key, and each call finds the network's
// keychain.
type sealedStoreLog struct {
	instance  *SidecarInstance
	networkId Id
	class     string
	// inside net/<network_id>
	path string
}

// Opens name as a log of this store's class. See SidecarStore.
func (self *sealedStore) Log(name string) (SidecarStoreLog, error) {
	if self.class == "" {
		return nil, ErrSidecarStoreNoClass
	}
	path, err := self.networkPath(name)
	if err != nil {
		return nil, err
	}
	if self.networkId == nil {
		return nil, ErrSidecarStoreLocked
	}
	return &sealedStoreLog{instance: self.instance, networkId: *self.networkId, class: self.class, path: path}, nil
}

// See SidecarStoreLog.
func (self *sealedStoreLog) Append(record []byte) error {
	if StoreLogRecordMaxByteCount < len(record) {
		return ErrStoreLogRecordTooLarge
	}
	self.instance.touch()
	opened, err := self.instance.keychainFor(self.networkId)
	if err != nil {
		return err
	}
	return opened.appendLog(self.class, self.path, record)
}

// See SidecarStoreLog.
func (self *sealedStoreLog) Read(visit func(index uint64, record []byte) error) error {
	self.instance.touch()
	opened, err := self.instance.keychainFor(self.networkId)
	if err != nil {
		return err
	}
	_, err = opened.readLog(self.class, self.path, true, visit)
	return err
}

// The AEAD of class under generation, holding that root until the release: what a log's reader opens with.
func (self *keychain) holdLogAead(class string) func(generation uint64) (cipher.AEAD, func(), error) {
	return func(generation uint64) (cipher.AEAD, func(), error) {
		held, err := self.holdGeneration(generation)
		if err != nil {
			return nil, nil, err
		}
		if held != generation {
			self.releaseGeneration(held)
			return nil, nil, errKeychainRootGone
		}
		self.instance.touch()
		aead, err := self.classAead(class, generation)
		if err != nil {
			self.releaseGeneration(held)
			return nil, nil, err
		}
		return aead, func() { self.releaseGeneration(held) }, nil
	}
}

// Reads the log at path, as readStoreLog does, answering ErrSidecarStoreAbsent for no file when absentIsError and
// an empty tail otherwise. A rotation can finish between the read of a header and the hold of its root, so a root
// gone at that moment means the file moved on, and the second read gets the new one.
func (self *keychain) readLog(class string, path string, absentIsError bool,
	visit func(index uint64, record []byte) error) (*storeLogTail, error) {
	read := func() (*storeLogTail, error) {
		in, err := self.instance.backend.Open(networkFilePath(self.networkId, path))
		if errors.Is(err, ErrSidecarStoreAbsent) && !absentIsError {
			return &storeLogTail{}, nil
		}
		if err != nil {
			return nil, err
		}
		defer in.Close()
		return readStoreLog(in, class, path, self.holdLogAead(class), visit)
	}
	tail, err := read()
	if errors.Is(err, errKeychainRootGone) {
		tail, err = read()
	}
	return tail, err
}

// Appends one sealed record to the log at path, by the steps the file comment gives. Lock order: the path's lock,
// then commitLock, so a rotation's swap and the keychain's close wait out an append in flight, and an append after
// either finds what they left.
func (self *keychain) appendLog(class string, path string, record []byte) error {
	pathState := self.logs.path(path)
	pathState.appendLock.Lock()
	defer pathState.appendLock.Unlock()
	self.commitLock.RLock()
	defer self.commitLock.RUnlock()
	if err := self.requireOpen(); err != nil {
		return err
	}

	backendPath := networkFilePath(self.networkId, path)
	file, created, err := self.instance.backend.OpenAppend(backendPath)
	if err != nil {
		return err
	}
	defer file.Close()
	size, err := file.Size()
	if err != nil {
		return err
	}
	tail := self.logs.tail(pathState)
	if tail == nil || tail.byteCount != size {
		// first use, or the file is not what the last append left: read it whole, every record checked
		tail, err = self.readLog(class, path, false, nil)
		if err != nil {
			return err
		}
	}
	if size < tail.byteCount {
		self.logs.setTail(pathState, nil)
		return errStoreLogShrank
	}

	generation := uint64(0)
	if tail.encodedHeader != nil {
		generation = tail.generation
	}
	generation, err = self.holdGeneration(generation)
	if err != nil {
		return err
	}
	defer self.releaseGeneration(generation)
	encodedHeader := tail.encodedHeader
	if encodedHeader == nil {
		header := &storeLogHeader{generation: generation, class: class}
		encodedHeader = header.encode()
	}
	aead, err := self.classAead(class, generation)
	if err != nil {
		return err
	}
	nonce := make([]byte, storeLogNonceByteCount, storeLogSealedMinByteCount+len(record))
	if _, err := io.ReadFull(self.instance.random, nonce); err != nil {
		return storeFault(err)
	}
	additionalData := storeLogAdditionalData(encodedHeader, path, tail.recordCount, &tail.previous)
	sealed := aead.Seal(nonce, nonce, record, additionalData)
	frame := storeLogFrame(len(sealed))

	out := make([]byte, 0, len(encodedHeader)+len(frame)+len(sealed))
	if tail.encodedHeader == nil {
		out = append(out, encodedHeader...)
	}
	out = append(out, frame...)
	out = append(out, sealed...)
	// whatever the file holds past the tail, a torn write or a header with no record, goes first
	if tail.byteCount < size {
		if err := file.Truncate(tail.byteCount); err != nil {
			self.logs.setTail(pathState, nil)
			return err
		}
	}
	if _, err := file.Write(out); err != nil {
		self.logs.setTail(pathState, nil)
		return err
	}
	if err := file.Sync(); err != nil {
		self.logs.setTail(pathState, nil)
		return err
	}
	if created || tail.encodedHeader == nil {
		if err := self.instance.backend.SyncDirectory(backendPath); err != nil {
			self.logs.setTail(pathState, nil)
			return err
		}
	}
	self.logs.setTail(pathState, &storeLogTail{
		byteCount:     tail.byteCount + int64(len(out)),
		recordCount:   tail.recordCount + 1,
		previous:      storeLogRecordHash(frame, sealed),
		encodedHeader: encodedHeader,
		generation:    generation,
	})
	stale := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return generation != self.currentGeneration
	}
	if stale() {
		// a log still on an old root, which the rotation's next pass must move
		self.staleCommitCount.Add(1)
	}
	return nil
}

// Moves the log at path to the current root, record by record, as resealFile moves a sealed file. Reports whether it
// had to. An append that lands between the copy and the swap wins: the copy is dropped, and the next pass looks
// again. A file holding no whole header holds no record, and stays for the next append to start over.
func (self *keychain) resealLog(path string) (bool, error) {
	self.instance.touch()
	backendPath := networkFilePath(self.networkId, path)
	in, err := self.instance.backend.Open(backendPath)
	if errors.Is(err, ErrSidecarStoreAbsent) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer in.Close()
	counted := &countingReader{in: in}
	buffered := bufio.NewReader(counted)
	header, torn, err := readStoreLogHeader(buffered)
	if err != nil || torn {
		return false, err
	}
	generation, err := self.holdGeneration(0)
	if err != nil {
		return false, err
	}
	defer self.releaseGeneration(generation)
	if header.generation == generation {
		return false, nil
	}
	newAead, err := self.classAead(header.class, generation)
	if err != nil {
		return false, err
	}

	file, err := self.instance.backend.CreateTemp()
	if err != nil {
		return false, err
	}
	defer file.Discard()
	newHeader := &storeLogHeader{generation: generation, class: header.class}
	encodedNewHeader := newHeader.encode()
	if _, err := file.Write(encodedNewHeader); err != nil {
		return false, err
	}
	var previous [sha256.Size]byte
	copyRecord := func(index uint64, record []byte) error {
		defer clear(record)
		nonce := make([]byte, storeLogNonceByteCount, storeLogSealedMinByteCount+len(record))
		if _, err := io.ReadFull(self.instance.random, nonce); err != nil {
			return storeFault(err)
		}
		additionalData := storeLogAdditionalData(encodedNewHeader, path, index, &previous)
		sealed := newAead.Seal(nonce, nonce, record, additionalData)
		frame := storeLogFrame(len(sealed))
		if _, err := file.Write(frame); err != nil {
			return err
		}
		if _, err := file.Write(sealed); err != nil {
			return err
		}
		previous = storeLogRecordHash(frame, sealed)
		return nil
	}
	// the header is read already, so the records follow from where it stopped
	prefixed := io.MultiReader(bytes.NewReader(header.encode()), buffered)
	if _, err := readStoreLog(prefixed, header.class, path, self.holdLogAead(header.class), copyRecord); err != nil {
		return false, err
	}
	if _, err := io.Copy(io.Discard, buffered); err != nil {
		return false, storeFault(err)
	}
	copiedByteCount := counted.byteCount

	replaced, err := func() (bool, error) {
		self.commitLock.Lock()
		defer self.commitLock.Unlock()
		currentIn, err := self.instance.backend.Open(backendPath)
		if errors.Is(err, ErrSidecarStoreAbsent) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		defer currentIn.Close()
		current, err := io.ReadAll(io.LimitReader(currentIn, copiedByteCount+1))
		if err != nil {
			return false, storeFault(err)
		}
		// the same header and the same length mean no append landed: appends only grow the file, and only under
		// commitLock, which this holds
		if int64(len(current)) != copiedByteCount || !bytes.HasPrefix(current, header.encode()) {
			return false, nil
		}
		if err := file.Sync(); err != nil {
			return false, err
		}
		if err := file.Rename(backendPath); err != nil {
			return false, err
		}
		self.logs.forget(path)
		return true, nil
	}()
	if err != nil || !replaced {
		return true, err
	}
	return true, self.instance.backend.SyncDirectory(backendPath)
}

// Counts what passes through, so a rotation knows how long the file it copied was.
type countingReader struct {
	in        io.Reader
	byteCount int64
}

// Reads from in.
func (self *countingReader) Read(p []byte) (int, error) {
	n, err := self.in.Read(p)
	self.byteCount += int64(n)
	return n, err
}
