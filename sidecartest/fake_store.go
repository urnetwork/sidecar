// A fake of sidecar.SidecarStore: one network's files in memory, unsealed, for tests outside the root that need a
// store to drive a component through, the real MLS engine's state among them. A Commit swaps a whole file in at
// once, a writer closed without one changes nothing, and a directory is a prefix of one shared map, as the real
// store's are of one network's directory. It seals nothing and checks no class: a test of the sealing itself uses
// the root's SidecarInstance on a memory backend.
//
// A test can make every write fail from some point on (FailWritesAfter) or read a file's bytes (Contents), which
// is how a kill between two writes is staged without a real crash.
//
// Safe for concurrent use; a writer has one owner.

package sidecartest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/urnetwork/sidecar"
)

// What FailWritesAfter makes every later write answer.
var ErrFakeStoreWriteFailed = errors.New("fake store: write failed")

// One store's files.
type FakeStore struct {
	stateLock    sync.Mutex
	pathContents map[string][]byte
	// writes still allowed before every write fails, or negative for no limit
	writesLeft int
}

func NewFakeStore() *FakeStore {
	return &FakeStore{pathContents: map[string][]byte{}, writesLeft: -1}
}

// After count more writes, a Commit or a Remove each, every write fails with ErrFakeStoreWriteFailed, as a
// process killed there would leave the store. Negative allows every write again.
func (self *FakeStore) FailWritesAfter(count int) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.writesLeft = count
}

// A copy of the bytes at path, from the store's root, and whether a file is there.
func (self *FakeStore) Contents(path string) ([]byte, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	content, ok := self.pathContents[path]
	return bytes.Clone(content), ok
}

// Every path the store holds, sorted.
func (self *FakeStore) Paths() []string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	paths := []string{}
	for path := range self.pathContents {
		paths = append(paths, path)
	}
	slices.Sort(paths)
	return paths
}

// The store's root directory, as a host hands a component the network's.
func (self *FakeStore) Root() sidecar.SidecarStore {
	return &fakeStoreDirectory{store: self}
}

// Whether a write may go ahead, counting it.
func (self *FakeStore) takeWriteWithLock() error {
	if self.writesLeft == 0 {
		return ErrFakeStoreWriteFailed
	}
	if 0 < self.writesLeft {
		self.writesLeft -= 1
	}
	return nil
}

// One directory of a FakeStore.
type fakeStoreDirectory struct {
	store *FakeStore
	// with a trailing / unless the root
	prefix string
}

// A clean relative name, as sidecar.SidecarStore's rule has it, in the root's terms.
func (self *fakeStoreDirectory) path(name string) (string, error) {
	if name == "" {
		return "", sidecar.ErrSidecarStoreName
	}
	for _, segment := range strings.Split(name, "/") {
		if segment == "" || segment[0] == '.' || strings.ContainsAny(segment, "\\:") {
			return "", sidecar.ErrSidecarStoreName
		}
	}
	return self.prefix + name, nil
}

func (self *fakeStoreDirectory) Open(name string) (io.ReadCloser, error) {
	path, err := self.path(name)
	if err != nil {
		return nil, err
	}
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	content, ok := self.store.pathContents[path]
	if !ok {
		return nil, sidecar.ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(bytes.Clone(content))), nil
}

func (self *fakeStoreDirectory) Create(name string) (sidecar.SidecarStoreWriter, error) {
	path, err := self.path(name)
	if err != nil {
		return nil, err
	}
	return &fakeStoreWriter{store: self.store, path: path}, nil
}

func (self *fakeStoreDirectory) Remove(name string) error {
	path, err := self.path(name)
	if err != nil {
		return err
	}
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	if _, ok := self.store.pathContents[path]; !ok {
		return nil
	}
	if err := self.store.takeWriteWithLock(); err != nil {
		return err
	}
	delete(self.store.pathContents, path)
	return nil
}

func (self *fakeStoreDirectory) List(prefix string) ([]sidecar.SidecarStoreEntry, error) {
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	entries := []sidecar.SidecarStoreEntry{}
	for path, content := range self.store.pathContents {
		name, ok := strings.CutPrefix(path, self.prefix)
		if ok && strings.HasPrefix(name, prefix) {
			entries = append(entries, sidecar.SidecarStoreEntry{Name: name, ByteCount: int64(len(content))})
		}
	}
	slices.SortFunc(entries, func(first sidecar.SidecarStoreEntry, second sidecar.SidecarStoreEntry) int {
		return strings.Compare(first.Name, second.Name)
	})
	return entries, nil
}

func (self *fakeStoreDirectory) Directory(name string, class string) (sidecar.SidecarStore, error) {
	if name == "" {
		return self, nil
	}
	path, err := self.path(name)
	if err != nil {
		return nil, err
	}
	return &fakeStoreDirectory{store: self.store, prefix: path + "/"}, nil
}

// A file on its way in, held until Commit.
type fakeStoreWriter struct {
	store     *FakeStore
	path      string
	content   bytes.Buffer
	committed bool
	closed    bool
}

func (self *fakeStoreWriter) Write(data []byte) (int, error) {
	if self.committed || self.closed {
		return 0, errors.New("fake store: write after commit or close")
	}
	return self.content.Write(data)
}

func (self *fakeStoreWriter) Commit() error {
	if self.committed || self.closed {
		return errors.New("fake store: commit after commit or close")
	}
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	if err := self.store.takeWriteWithLock(); err != nil {
		return err
	}
	self.store.pathContents[self.path] = bytes.Clone(self.content.Bytes())
	self.committed = true
	return nil
}

func (self *fakeStoreWriter) Close() error {
	self.closed = true
	return nil
}

// A log at name, unsealed: each record a 4-byte big-endian length and its bytes, appended in place. An Append
// counts as a write for FailWritesAfter, and fails whole, so a staged kill leaves no torn record here: torn tails
// are the real log's, tested in the root.
func (self *fakeStoreDirectory) Log(name string) (sidecar.SidecarStoreLog, error) {
	path, err := self.path(name)
	if err != nil {
		return nil, err
	}
	return &fakeStoreLog{store: self.store, path: path}, nil
}

// One log of a FakeStore.
type fakeStoreLog struct {
	store *FakeStore
	path  string
}

// Appends the record under the store's lock, so appends to one path go one at a time.
func (self *fakeStoreLog) Append(record []byte) error {
	if sidecar.StoreLogRecordMaxByteCount < len(record) {
		return sidecar.ErrStoreLogRecordTooLarge
	}
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	if err := self.store.takeWriteWithLock(); err != nil {
		return err
	}
	content := bytes.Clone(self.store.pathContents[self.path])
	content = binary.BigEndian.AppendUint32(content, uint32(len(record)))
	self.store.pathContents[self.path] = append(content, record...)
	return nil
}

// Hands each record to visit in order, from a copy taken under the lock.
func (self *fakeStoreLog) Read(visit func(index uint64, record []byte) error) error {
	content, ok := self.store.Contents(self.path)
	if !ok {
		return sidecar.ErrSidecarStoreAbsent
	}
	for index := uint64(0); 0 < len(content); index += 1 {
		if len(content) < 4 || len(content)-4 < int(binary.BigEndian.Uint32(content)) {
			return sidecar.ErrSidecarStoreFailed
		}
		byteCount := int(binary.BigEndian.Uint32(content))
		if err := visit(index, bytes.Clone(content[4:4+byteCount])); err != nil {
			return err
		}
		content = content[4+byteCount:]
	}
	return nil
}
