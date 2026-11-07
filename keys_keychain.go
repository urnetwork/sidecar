// The keychain: one network's open root keys and its decoded keychain.ur (§5.9). A keychain exists
// only while its instance is open, and locking zeroes it, so every call below it can answer
// ErrSidecarStoreLocked.
//
// keychain.ur is one sealed file (state_seal.go) of class keychain, over these records:
//
//	magic "URKR" | version 1 | count, uint32 | record ...
//	record: name length, uint16 | name | value length, uint32 | value
//
// sorted by name, each name once, integers big endian. A component's secrets are records under
// <namespace>/. Writing one rewrites the file, which is small: identities, keys and statements in
// flight, never content.
//
// Locks: commitLock orders a file's swap against a rotation's re-seal of that file and against close,
// and persistLock orders writes of keychain.ur, and both are held across I/O, so neither is stateLock
// and neither is taken under it. Order: persistLock, then commitLock, then stateLock.
//
// An unlock opens a new keychain over the same files, so nothing this one writes may land once it has
// closed: close waits out a swap or a removal already holding commitLock, and every later one finds it
// closed under commitLock and refuses.

package sidecar

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
)

// The format's values. keychainMaxByteCount bounds what one network's secrets may come to, which every
// host must fit in memory at once, the smallest budget being 16 MiB (§18.4), so it is not a tunable.
const (
	keychainRecordsMagic     = "URKR"
	keychainRecordsVersion   = 1
	keychainRecordsClass     = "keychain"
	keychainNameMaxByteCount = 1024
	keychainMaxByteCount     = 16 * 1024 * 1024
)

var errKeychainRecordsFormat = fmt.Errorf("%w: keychain records do not decode", ErrSidecarStoreFailed)

// A file's header names a root this keychain does not hold.
var errKeychainRootGone = fmt.Errorf("%w: a sealed file's root is gone", ErrSidecarStoreFailed)

// keychain.ur's plaintext for these records.
func encodeKeychainRecords(nameValues map[string][]byte) []byte {
	byteCount := len(keychainRecordsMagic) + 1 + 4
	for name, value := range nameValues {
		byteCount += 2 + len(name) + 4 + len(value)
	}
	encoded := make([]byte, 0, byteCount)
	encoded = append(encoded, keychainRecordsMagic...)
	encoded = append(encoded, keychainRecordsVersion)
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(nameValues)))
	for _, name := range slices.Sorted(maps.Keys(nameValues)) {
		value := nameValues[name]
		encoded = binary.BigEndian.AppendUint16(encoded, uint16(len(name)))
		encoded = append(encoded, name...)
		encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(value)))
		encoded = append(encoded, value...)
	}
	return encoded
}

// The records of encoded, which is keychain.ur's plaintext and so has passed AEAD, but a decoder here
// stays total: nothing is allocated past what the input holds, and an error never repeats it.
func decodeKeychainRecords(encoded []byte) (map[string][]byte, error) {
	cursor := &wrapCursor{remaining: encoded}
	if string(cursor.take(len(keychainRecordsMagic))) != keychainRecordsMagic ||
		cursor.takeUint8() != keychainRecordsVersion {
		return nil, errKeychainRecordsFormat
	}
	count := cursor.takeUint32()
	nameValues := map[string][]byte{}
	previousName := ""
	for i := uint32(0); i < count; i += 1 {
		nameByteCount := int(cursor.takeUint16())
		name := string(cursor.take(nameByteCount))
		valueByteCount := cursor.takeUint32()
		if keychainMaxByteCount < valueByteCount {
			return nil, errKeychainRecordsFormat
		}
		value := cursor.take(int(valueByteCount))
		if cursor.failed || name == "" || keychainNameMaxByteCount < nameByteCount ||
			(i != 0 && name <= previousName) {
			return nil, errKeychainRecordsFormat
		}
		nameValues[name] = bytes.Clone(value)
		previousName = name
	}
	if !cursor.finished() {
		return nil, errKeychainRecordsFormat
	}
	return nameValues, nil
}

// One derived file key.
type keychainClassKey struct {
	class      string
	generation uint64
}

// One network's root keys and secrets (D-CORE-14). Holds nothing of any other network, which is what
// keeps one network's material from opening another's. Safe for concurrent use.
type keychain struct {
	instance  *SidecarInstance
	networkId Id
	// what §22.4's hooks key this network's steps by
	hookKey string

	persistLock sync.Mutex
	commitLock  sync.RWMutex

	stateLock sync.Mutex
	closed    bool
	// R_n by root generation. Holds more than one only during a rotation.
	generationRoots   map[uint64][]byte
	currentGeneration uint64
	classKeys         map[keychainClassKey][]byte
	records           map[string][]byte
	// streams open on each generation, which a rotation may not drop from under them
	generationStreams map[uint64]int

	// files committed under a root that had stopped being current, which a rotation must then
	// re-seal, however far its pass has got
	staleCommitCount atomic.Int64
}

// Open over generationRoots, which it takes, with its records still to load.
func newKeychain(instance *SidecarInstance, networkId Id, generationRoots map[uint64][]byte, currentGeneration uint64) *keychain {
	return &keychain{
		instance:          instance,
		networkId:         networkId,
		hookKey:           networkId.String(),
		generationRoots:   generationRoots,
		currentGeneration: currentGeneration,
		classKeys:         map[keychainClassKey][]byte{},
		records:           map[string][]byte{},
		generationStreams: map[uint64]int{},
	}
}

// Zeroes everything it holds, as far as Go lets a program, once a swap in flight has landed. Every later
// call answers ErrSidecarStoreLocked, a stream's next chunk and a later commit included.
func (self *keychain) close() {
	if !self.commitLock.TryLock() {
		// marks that this close, under the instance's operationLock, waits on a swap in flight
		testHookBarrier("keys.keychain_close.wait", self.hookKey)
		self.commitLock.Lock()
	}
	defer self.commitLock.Unlock()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.closed = true
	for _, root := range self.generationRoots {
		clear(root)
	}
	for _, key := range self.classKeys {
		clear(key)
	}
	for _, value := range self.records {
		clear(value)
	}
	self.generationRoots = nil
	self.classKeys = nil
	self.records = nil
}

// A class's key under a root, derived once. The hook runs with no lock held.
func (self *keychain) classKey(class string, generation uint64) ([]byte, error) {
	classKey := keychainClassKey{class: class, generation: generation}
	var key []byte
	var root []byte
	err := func() error {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.closed {
			return ErrSidecarStoreLocked
		}
		var ok bool
		if key, ok = self.classKeys[classKey]; ok {
			return nil
		}
		if root, ok = self.generationRoots[generation]; !ok {
			return errSealOpen
		}
		root = bytes.Clone(root)
		return nil
	}()
	if err != nil {
		return nil, err
	}
	if key != nil {
		return key, nil
	}
	defer clear(root)
	key, err = deriveLocalKey(root, class)
	if err != nil {
		return nil, err
	}
	testHookSecret("K_local", key)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		clear(key)
		return nil, ErrSidecarStoreLocked
	}
	self.classKeys[classKey] = key
	return key, nil
}

// A class's AEAD, asked for at each chunk so a lock stops every stream at its next one. The AEAD keeps
// its own copy of the key, so a close cannot race a chunk in flight.
func (self *keychain) classAead(class string, generation uint64) (cipher.AEAD, error) {
	key, err := self.classKey(class, generation)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, ErrSidecarStoreLocked
	}
	return chacha20poly1305.NewX(key)
}

// Counts a stream on generation, so a rotation keeps its root. Answers the current generation when
// asked for 0, and errKeychainRootGone for a root this keychain does not hold.
func (self *keychain) holdGeneration(generation uint64) (uint64, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return 0, ErrSidecarStoreLocked
	}
	if generation == 0 {
		generation = self.currentGeneration
	}
	if _, ok := self.generationRoots[generation]; !ok {
		return 0, errKeychainRootGone
	}
	self.generationStreams[generation] += 1
	return generation, nil
}

// Takes the roots of keychain.wrap this keychain does not hold, and makes currentGeneration current, for
// a resumed rotation. A root held already is the same key: one reaches memory only from that file or
// from a write of it that succeeded.
func (self *keychain) adoptRoots(generationRoots map[uint64][]byte, currentGeneration uint64) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		for _, root := range generationRoots {
			clear(root)
		}
		return ErrSidecarStoreLocked
	}
	for generation, root := range generationRoots {
		if _, ok := self.generationRoots[generation]; ok {
			clear(root)
			continue
		}
		self.generationRoots[generation] = root
	}
	self.currentGeneration = currentGeneration
	return nil
}

// Ends what holdGeneration began.
func (self *keychain) releaseGeneration(generation uint64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return
	}
	self.generationStreams[generation] -= 1
	if self.generationStreams[generation] <= 0 {
		delete(self.generationStreams, generation)
	}
}

// Streams the file at path, which fails at its first chunk unless it is of class, since only that
// class's key opens it. The header's generation picks the root, so a file not yet re-sealed by a
// rotation still opens. A rotation can finish between reading a header and
// holding its root, so a root gone at that moment means the file has moved on: the second read gets
// the new one. A root still gone then is a file naming a root this network never had.
func (self *keychain) openSealed(class string, path string) (io.ReadCloser, error) {
	self.instance.touch()
	open := func() (io.ReadCloser, error) {
		in, err := self.instance.backend.Open(networkFilePath(self.networkId, path))
		if err != nil {
			return nil, err
		}
		header, err := readSealHeader(in)
		if err != nil {
			in.Close()
			return nil, err
		}
		generation, err := self.holdGeneration(header.generation)
		if err != nil {
			in.Close()
			return nil, err
		}
		reader := newSealReader(in, header, path, func() (cipher.AEAD, error) {
			self.instance.touch()
			return self.classAead(class, header.generation)
		})
		return &sealedFileReader{keychain: self, reader: reader, in: in, generation: generation}, nil
	}
	reader, err := open()
	if errors.Is(err, errKeychainRootGone) {
		reader, err = open()
	}
	return reader, err
}

// A sealed file on its way out.
type sealedFileReader struct {
	keychain   *keychain
	reader     *sealReader
	in         io.Closer
	generation uint64
	closed     bool
}

// Hands out authenticated plaintext.
func (self *sealedFileReader) Read(p []byte) (int, error) {
	return self.reader.Read(p)
}

// Ends the stream. Safe to call again.
func (self *sealedFileReader) Close() error {
	if self.closed {
		return nil
	}
	self.closed = true
	self.keychain.releaseGeneration(self.generation)
	return self.in.Close()
}

// Starts a sealed write of path, under the current root. Nothing shows until Commit.
func (self *keychain) createSealed(class string, path string) (*sealedFileWriter, error) {
	self.instance.touch()
	generation, err := self.holdGeneration(0)
	if err != nil {
		return nil, err
	}
	writer, err := self.newSealedWriter(class, path, generation)
	if err != nil {
		self.releaseGeneration(generation)
		return nil, err
	}
	return writer, nil
}

// A writer holding generation, which Close releases.
func (self *keychain) newSealedWriter(class string, path string, generation uint64) (*sealedFileWriter, error) {
	header := &sealHeader{generation: generation, class: class}
	if _, err := io.ReadFull(self.instance.random, header.noncePrefix[:]); err != nil {
		return nil, storeFault(err)
	}
	file, err := self.instance.backend.CreateTemp()
	if err != nil {
		return nil, storeFault(err)
	}
	seal, err := newSealWriter(file, header, path, func() (cipher.AEAD, error) {
		self.instance.touch()
		return self.classAead(class, generation)
	})
	if err != nil {
		file.Discard()
		return nil, storeFault(err)
	}
	return &sealedFileWriter{keychain: self, file: file, seal: seal, path: path, generation: generation}, nil
}

// A sealed file on its way in.
type sealedFileWriter struct {
	keychain   *keychain
	file       SidecarStoreBackendFile
	seal       *sealWriter
	path       string
	generation uint64
	committed  bool
	closed     bool
}

// Takes plaintext, which reaches the temp file only sealed.
func (self *sealedFileWriter) Write(p []byte) (int, error) {
	if self.closed || self.committed {
		return 0, ErrSidecarStoreFailed
	}
	return self.seal.Write(p)
}

// Seals the end of the file and swaps it in, by §5.9's steps. Afterward only Close is left.
func (self *sealedFileWriter) Commit() error {
	testHookBarrier("state.commit.before", self.keychain.hookKey)
	err := self.commitFile()
	testHookBarrier("state.commit.after", self.keychain.hookKey)
	return err
}

// Commit without its barriers, for a caller holding a lock no barrier may stall behind.
func (self *sealedFileWriter) commitFile() error {
	if self.closed || self.committed {
		return ErrSidecarStoreFailed
	}
	self.committed = true
	if err := self.seal.finish(); err != nil {
		return err
	}
	self.keychain.commitLock.RLock()
	defer self.keychain.commitLock.RUnlock()
	if err := self.keychain.requireOpen(); err != nil {
		return err
	}
	err := commitBackendFile(
		self.keychain.instance.backend,
		self.file,
		networkFilePath(self.keychain.networkId, self.path),
	)
	stale := func() bool {
		self.keychain.stateLock.Lock()
		defer self.keychain.stateLock.Unlock()
		return self.generation != self.keychain.currentGeneration
	}
	if stale() {
		self.keychain.staleCommitCount.Add(1)
	}
	return err
}

// Drops the file unless Commit swapped it in. Safe to call again.
func (self *sealedFileWriter) Close() error {
	if self.closed {
		return nil
	}
	self.closed = true
	self.seal.abandon()
	self.keychain.releaseGeneration(self.generation)
	return self.file.Discard()
}

// Takes the file at path away. A locked keychain deletes nothing (D-CORE-15).
func (self *keychain) removeSealed(path string) error {
	self.instance.touch()
	backendPath := networkFilePath(self.networkId, path)
	self.commitLock.RLock()
	defer self.commitLock.RUnlock()
	if err := self.requireOpen(); err != nil {
		return err
	}
	if err := self.instance.backend.Remove(backendPath); err != nil {
		return err
	}
	return self.instance.backend.SyncDirectory(backendPath)
}

// ErrSidecarStoreLocked once this keychain has closed.
func (self *keychain) requireOpen() error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return ErrSidecarStoreLocked
	}
	return nil
}

// The files under base, a directory inside the network ending in /, or empty, whose names start with
// prefix, named relative to base. The keychain's own two files are not a store's to see.
func (self *keychain) listSealed(base string, prefix string) ([]SidecarStoreEntry, error) {
	self.instance.touch()
	if err := self.requireOpen(); err != nil {
		return nil, err
	}
	directory := networkDirectoryPath(self.networkId) + "/"
	backendEntries, err := self.instance.backend.List(directory + base + prefix)
	if err != nil {
		return nil, err
	}
	entries := make([]SidecarStoreEntry, 0, len(backendEntries))
	for _, entry := range backendEntries {
		name := strings.TrimPrefix(entry.Name, directory)
		if name == keychainWrapName || name == keychainRecordsName {
			continue
		}
		entries = append(entries, SidecarStoreEntry{Name: strings.TrimPrefix(name, base), ByteCount: entry.ByteCount})
	}
	return entries, nil
}

// Reads keychain.ur into memory, the records staying empty if none has been written. Whether that is
// fine is the caller's to say, which knows if a sidecar_id is recorded here.
func (self *keychain) loadRecords() error {
	reader, err := self.openSealed(keychainRecordsClass, keychainRecordsName)
	if err != nil {
		return err
	}
	defer reader.Close()
	encoded, err := io.ReadAll(io.LimitReader(reader, keychainMaxByteCount+1))
	if err != nil {
		return err
	}
	defer clear(encoded)
	if keychainMaxByteCount < len(encoded) {
		return errKeychainRecordsFormat
	}
	records, err := decodeKeychainRecords(encoded)
	if err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return ErrSidecarStoreLocked
	}
	self.records = records
	return nil
}

// Applies edit to a copy of the records, seals the copy into keychain.ur, and only then makes it what
// this keychain reads, so memory never runs ahead of the disk. A kill leaves the old file or the new one
// (§22.8). A keychain that closed once the swap had landed answers nil and keeps nothing, since the disk
// has the write and the keychain opened next reads it; one that closed first refuses the swap.
func (self *keychain) updateRecords(edit func(nameValues map[string][]byte)) error {
	testHookBarrier("keys.keychain_write.before", self.hookKey)
	err := func() error {
		self.persistLock.Lock()
		defer self.persistLock.Unlock()

		var next map[string][]byte
		var encoded []byte
		err := func() error {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if self.closed {
				return ErrSidecarStoreLocked
			}
			next = maps.Clone(self.records)
			edit(next)
			encoded = encodeKeychainRecords(next)
			return nil
		}()
		if err != nil {
			return err
		}
		defer clear(encoded)
		if keychainMaxByteCount < len(encoded) {
			return fmt.Errorf("%w: keychain over its bound", ErrSidecarStoreFailed)
		}
		writer, err := self.createSealed(keychainRecordsClass, keychainRecordsName)
		if err != nil {
			return err
		}
		defer writer.Close()
		if _, err := writer.Write(encoded); err != nil {
			return err
		}
		if err := writer.commitFile(); err != nil {
			return err
		}

		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if !self.closed {
			self.records = next
		}
		return nil
	}()
	testHookBarrier("keys.keychain_write.after", self.hookKey)
	return err
}

// The record under recordName, a copy.
func (self *keychain) getRecord(recordName string) ([]byte, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, ErrSidecarStoreLocked
	}
	value, ok := self.records[recordName]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return bytes.Clone(value), nil
}

// The names of the records under namespacePrefix, without it, that start with prefix, sorted.
func (self *keychain) listRecords(namespacePrefix string, prefix string) ([]string, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.closed {
		return nil, ErrSidecarStoreLocked
	}
	names := []string{}
	for recordName := range self.records {
		if name, ok := strings.CutPrefix(recordName, namespacePrefix); ok && strings.HasPrefix(name, prefix) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names, nil
}

// A component's view of network networkId's keychain, its names under namespace: what SidecarEnv.Secrets
// carries for a whole generation. Like a store it holds no key, and each call finds the network's
// keychain, so it answers ErrSidecarStoreLocked while the instance is locked and works again once it
// opens.
func (self *SidecarInstance) secrets(networkId Id, namespace string) SidecarSecrets {
	return &keychainSecrets{instance: self, networkId: networkId, prefix: namespace + "/"}
}

// The same view, of this keychain's network.
func (self *keychain) secrets(namespace string) SidecarSecrets {
	return self.instance.secrets(self.networkId, namespace)
}

// The SidecarSecrets implementation.
type keychainSecrets struct {
	instance  *SidecarInstance
	networkId Id
	prefix    string
}

// The record name of name, or ErrSidecarStoreName.
func (self *keychainSecrets) recordName(name string) (string, error) {
	recordName := self.prefix + name
	if name == "" || keychainNameMaxByteCount < len(recordName) {
		return "", ErrSidecarStoreName
	}
	return recordName, nil
}

// A copy of the value. See SidecarSecrets.
func (self *keychainSecrets) Get(name string) ([]byte, error) {
	recordName, err := self.recordName(name)
	if err != nil {
		return nil, err
	}
	self.instance.touch()
	opened, err := self.instance.keychainFor(self.networkId)
	if err != nil {
		return nil, err
	}
	return opened.getRecord(recordName)
}

// Keeps a copy of the value. See SidecarSecrets.
func (self *keychainSecrets) Put(name string, value []byte) error {
	recordName, err := self.recordName(name)
	if err != nil {
		return err
	}
	opened, err := self.instance.keychainFor(self.networkId)
	if err != nil {
		return err
	}
	stored := bytes.Clone(value)
	if stored == nil {
		stored = []byte{}
	}
	return opened.updateRecords(func(nameValues map[string][]byte) {
		nameValues[recordName] = stored
	})
}

// Takes name away. See SidecarSecrets.
func (self *keychainSecrets) Delete(name string) error {
	recordName, err := self.recordName(name)
	if err != nil {
		return err
	}
	opened, err := self.instance.keychainFor(self.networkId)
	if err != nil {
		return err
	}
	return opened.updateRecords(func(nameValues map[string][]byte) {
		delete(nameValues, recordName)
	})
}

// The names under prefix. See SidecarSecrets.
func (self *keychainSecrets) List(prefix string) ([]string, error) {
	self.instance.touch()
	opened, err := self.instance.keychainFor(self.networkId)
	if err != nil {
		return nil, err
	}
	return opened.listRecords(self.prefix, prefix)
}
