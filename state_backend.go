// The medium under an instance's state. Everything sealed or wrapped goes through SidecarStoreBackend,
// so no layer above it touches os: desktops and apps use state_backend_os.go, the page Worker's main
// brings IndexedDB (§18.10), and an ephemeral sidecar stays in memory here, writing nothing anywhere
// (§5.6). A backend only ever holds ciphertext, sidecar.json aside, which holds nothing secret.
//
// A write is §5.9's steps, each a call so a fault schedule can stop between any two:
//
//	CreateTemp, Write..., Sync, Rename, SyncDirectory
//
// so a kill leaves the old file or the new one, and an fsync comes before the rename that exposes
// the bytes. commitBackendFile runs the last three in that order.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"sync"
)

// Bytes by path, with / between segments and relative to the instance's state. A read that finds
// nothing answers ErrSidecarStoreAbsent and any other failure wraps ErrSidecarStoreFailed, so a fault
// never reads as nothing there (D-CORE-15). An error never carries a path (I-13). Safe for concurrent
// use.
type SidecarStoreBackend interface {
	// Streams the bytes at path.
	Open(path string) (io.ReadCloser, error)
	// A new file with no path yet.
	CreateTemp() (SidecarStoreBackendFile, error)
	// Makes the directory entry a Rename to path made survive a power cut. A medium that needs no
	// such step, as a single transaction does not, answers nil.
	SyncDirectory(path string) error
	// Takes path away. Nothing there is not an error.
	Remove(path string) error
	// Each file whose path starts with prefix, sorted by path, with Name its whole path. Temp files
	// are never listed.
	List(prefix string) ([]SidecarStoreEntry, error)
	// Drops what a kill left of CreateTemp's files. An instance calls this once, on opening, while
	// no file is being written.
	RemoveTemp() error
}

// A file on its way to a path. Not safe for concurrent use.
type SidecarStoreBackendFile interface {
	io.Writer
	// Makes what was written survive a power cut.
	Sync() error
	// Ends the file and swaps it in at path whole, making path's directories as needed. A reader
	// sees the old file or this one, never a part (§22.9's no torn writes).
	Rename(path string) error
	// Drops the file. Does nothing after Rename, and is safe to call again.
	Discard() error
}

// The last three of a write's steps, in their order. The caller still holds file for Discard.
func commitBackendFile(backend SidecarStoreBackend, file SidecarStoreBackendFile, path string) error {
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Rename(path); err != nil {
		return err
	}
	return backend.SyncDirectory(path)
}

// A whole small file, by §5.9's steps.
func writeBackendFile(backend SidecarStoreBackend, path string, content []byte) error {
	file, err := backend.CreateTemp()
	if err != nil {
		return err
	}
	defer file.Discard()
	if _, err := file.Write(content); err != nil {
		return err
	}
	return commitBackendFile(backend, file, path)
}

// A whole small file of at most maxByteCount, since what sits on a medium is not trusted to be the size
// it should be. A longer one is ErrSidecarStoreFailed.
func readBackendFile(backend SidecarStoreBackend, path string, maxByteCount int) ([]byte, error) {
	reader, err := backend.Open(path)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, int64(maxByteCount)+1))
	if err != nil {
		return nil, storeFault(err)
	}
	if maxByteCount < len(content) {
		return nil, ErrSidecarStoreFailed
	}
	return content, nil
}

// A medium's error as a failure. Only the bare cause survives, since an os error carries its path.
func storeFault(err error) error {
	if errors.Is(err, ErrSidecarStoreAbsent) || errors.Is(err, ErrSidecarStoreFailed) ||
		errors.Is(err, ErrSidecarStoreLocked) {
		return err
	}
	for cause := errors.Unwrap(err); cause != nil; cause = errors.Unwrap(err) {
		err = cause
	}
	return fmt.Errorf("%w: %v", ErrSidecarStoreFailed, err)
}

// Everything in memory, for an ephemeral sidecar and for tests. Dies with the process, and writes
// nothing anywhere (§5.6).
func NewSidecarMemoryBackend() SidecarStoreBackend {
	return &memoryStoreBackend{
		pathContents: map[string][]byte{},
	}
}

// A file's bytes never change once committed, so a reader needs no copy.
type memoryStoreBackend struct {
	stateLock    sync.Mutex
	pathContents map[string][]byte
}

// Answers a reader over the bytes at path.
func (self *memoryStoreBackend) Open(path string) (io.ReadCloser, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	content, ok := self.pathContents[path]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

// A buffer, which reaches the map at Rename.
func (self *memoryStoreBackend) CreateTemp() (SidecarStoreBackendFile, error) {
	return &memoryStoreFile{backend: self}, nil
}

// A write here is already whole.
func (self *memoryStoreBackend) SyncDirectory(path string) error {
	return nil
}

// Forgets path.
func (self *memoryStoreBackend) Remove(path string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.pathContents, path)
	return nil
}

// Walks the map, which is small wherever this backend is used.
func (self *memoryStoreBackend) List(prefix string) ([]SidecarStoreEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for path, content := range self.pathContents {
		if strings.HasPrefix(path, prefix) {
			entries = append(entries, SidecarStoreEntry{Name: path, ByteCount: int64(len(content))})
		}
	}
	slices.SortFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int {
		return strings.Compare(a.Name, b.Name)
	})
	return entries, nil
}

// No temp file outlives a process here.
func (self *memoryStoreBackend) RemoveTemp() error {
	return nil
}

// A write not yet swapped in.
type memoryStoreFile struct {
	backend *memoryStoreBackend
	buffer  bytes.Buffer
	done    bool
}

// Buffers p.
func (self *memoryStoreFile) Write(p []byte) (int, error) {
	if self.done {
		return 0, ErrSidecarStoreFailed
	}
	return self.buffer.Write(p)
}

// Memory is as durable as this backend gets.
func (self *memoryStoreFile) Sync() error {
	return nil
}

// Publishes the buffer at path.
func (self *memoryStoreFile) Rename(path string) error {
	if self.done {
		return ErrSidecarStoreFailed
	}
	self.done = true
	content := bytes.Clone(self.buffer.Bytes())
	self.backend.stateLock.Lock()
	defer self.backend.stateLock.Unlock()
	self.backend.pathContents[path] = content
	return nil
}

// Drops the buffer.
func (self *memoryStoreFile) Discard() error {
	self.done = true
	self.buffer.Reset()
	return nil
}

// A SidecarKeyStore in memory, for an ephemeral sidecar with no OS store to use: a quick burner or
// `ur connect --ephemeral`. What it holds dies with the process (§5.6). Safe for concurrent use.
func NewSidecarMemoryKeyStore() SidecarKeyStore {
	return &memoryKeyStore{
		nameValues: map[string][]byte{},
	}
}

// Secrets by name.
type memoryKeyStore struct {
	stateLock  sync.Mutex
	nameValues map[string][]byte
}

// Always takes.
func (self *memoryKeyStore) PutSecret(name string, value []byte) SidecarKeyStoreStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nameValues[name] = bytes.Clone(value)
	return SidecarKeyStoreOk
}

// A copy, or Absent.
func (self *memoryKeyStore) GetSecret(name string) ([]byte, SidecarKeyStoreStatus) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	value, ok := self.nameValues[name]
	if !ok {
		return nil, SidecarKeyStoreAbsent
	}
	return bytes.Clone(value), SidecarKeyStorePresent
}

// Ok either way, as the interface has it.
func (self *memoryKeyStore) DeleteSecret(name string) SidecarKeyStoreStatus {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.nameValues, name)
	return SidecarKeyStoreOk
}
