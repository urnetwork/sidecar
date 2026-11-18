//go:build !ios_extension

// A SidecarStore kept in memory alone (§5.9's bounds row): the index cache's on an ephemeral sidecar
// (state_search_cache.go) and a phone's open directory view (directory_phone.go, §16.11's phones row), each of which
// writes nothing to any medium and loses it all with the process or at Close. It is a file of its own because the
// directory's view needs nothing else of the cache: the ios_extension legs' file closure, which reads files whatever
// their tags, names the view, and through this file reaches no index code (QD-988).
//
// On every leg but the ios_extension legs, which keep no index cache and open no directory view. Safe for concurrent
// use.

package sidecar

import (
	"bytes"
	"io"
	"slices"
	"strings"
	"sync"
)

// The store of a cache kept in memory (Search.CacheByteCount 0): an ephemeral sidecar's, which writes nothing to any
// medium and dies with the process (§5.9's bounds row). A SidecarStore over a map, every name in one flat space.
type searchMemoryStore struct {
	stateLock sync.Mutex
	files     map[string][]byte
}

// An empty memory store.
func newSearchMemoryStore() *searchMemoryStore {
	return &searchMemoryStore{files: map[string][]byte{}}
}

// The file's bytes. See SidecarStore.
func (self *searchMemoryStore) Open(name string) (io.ReadCloser, error) {
	if !isStoreName(name) {
		return nil, ErrSidecarStoreName
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	content, ok := self.files[name]
	if !ok {
		return nil, ErrSidecarStoreAbsent
	}
	return io.NopCloser(bytes.NewReader(content)), nil
}

// A writer swapping the file in whole at Commit. See SidecarStore.
func (self *searchMemoryStore) Create(name string) (SidecarStoreWriter, error) {
	if !isStoreName(name) {
		return nil, ErrSidecarStoreName
	}
	return &searchMemoryWriter{store: self, name: name}, nil
}

// Takes the file away. See SidecarStore.
func (self *searchMemoryStore) Remove(name string) error {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.files, name)
	return nil
}

// The files whose names start with prefix, sorted. See SidecarStore.
func (self *searchMemoryStore) List(prefix string) ([]SidecarStoreEntry, error) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entries := []SidecarStoreEntry{}
	for name, content := range self.files {
		if strings.HasPrefix(name, prefix) {
			// named from the store's directory, as a sealed store's listing names them
			entries = append(entries, SidecarStoreEntry{Name: name, ByteCount: int64(len(content))})
		}
	}
	slices.SortFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int { return strings.Compare(a.Name, b.Name) })
	return entries, nil
}

// The cache uses one flat space: narrowing is refused, as nothing asks for it.
func (self *searchMemoryStore) Directory(name string, class string) (SidecarStore, error) {
	return nil, ErrSidecarStoreName
}

// Drops every file.
func (self *searchMemoryStore) clear() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.files)
}

// A file on its way into the memory store, swapped in whole at Commit.
type searchMemoryWriter struct {
	store  *searchMemoryStore
	name   string
	buffer bytes.Buffer
	done   bool
}

// Buffers p until Commit.
func (self *searchMemoryWriter) Write(p []byte) (int, error) {
	if self.done {
		return 0, ErrSidecarStoreFailed
	}
	return self.buffer.Write(p)
}

// Swaps the file in whole.
func (self *searchMemoryWriter) Commit() error {
	if self.done {
		return ErrSidecarStoreFailed
	}
	self.done = true
	self.store.stateLock.Lock()
	defer self.store.stateLock.Unlock()
	self.store.files[self.name] = bytes.Clone(self.buffer.Bytes())
	return nil
}

// Drops what Commit did not take. Safe to call again.
func (self *searchMemoryWriter) Close() error {
	self.done = true
	self.buffer.Reset()
	return nil
}
