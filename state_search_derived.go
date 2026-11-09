// §5.9's derived data (CORE-M10-01): what a device computes from the index files it keeps, sealed under the local search
// key, the file's name carrying repo || ref || path || version || part in its AAD (state_search_cache.go): the search
// manifest, each shard's dictionary block index and n_d array, the version table (CORE-M10-02), and on desktops the
// local layer, mismatched entries and the local vocabulary; and a reproduced index file's plaintext (§11.14's reproduce
// row), which a device that rebuilt a merge, roll-up or CLOSURE from files it holds keeps instead of a download, once
// its SHA-256 equals the entry version's content_sha256. Every part is kept in 64 KiB frames, one file each, so a reader
// decrypts one frame at a time, by index (SearchCacheFrames).
//
// The parts are a closed list, so nothing a search asks or finds has a place here (§5.9's never row): no query, hit,
// snippet, cursor or result count. A part of one index file is kept only while the cache holds that file, as a record
// or reproduced; a part of a whole ref or index root (the manifest, the version table, the local layer, mismatches, the
// vocabulary) names the root's path, or "/" for the ref, and the ref version it is of.
//
// Decoded state lives in memory, in an LRU within Search.MemoryByteCount, with the version table's pages in their own
// within Search.VersionCacheByteCount (§5.9's bounds row); a lock drops both (SearchCache.Locked).
//
// On every leg: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// One kind of derived data (§5.9's holds row). A closed list: a part not here is refused.
type SearchCachePart string

const (
	// A reproduced index file's plaintext, checked against its entry version's content_sha256 (§11.14's reproduce row).
	SearchCachePartFile SearchCachePart = "file"
	// A shard's dictionary block index.
	SearchCachePartBlockIndex SearchCachePart = "blocks"
	// A shard's n_d array.
	SearchCachePartDocCounts SearchCachePart = "doc-counts"
	// The ref's search manifest, of a ref version.
	SearchCachePartManifest SearchCachePart = "manifest"
	// The version table's runs and pages, of an index root at a ref version (CORE-M10-02).
	SearchCachePartVersionTable SearchCachePart = "versions"
	// Desktops: the local layer, commits past indexed_through this device indexed from its own plaintext.
	SearchCachePartLocalLayer SearchCachePart = "local"
	// Desktops: entries a host with the text found mismatched.
	SearchCachePartMismatch SearchCachePart = "mismatch"
	// Desktops: the local vocabulary, words with their document counts.
	SearchCachePartVocabulary SearchCachePart = "vocabulary"
)

// The path a part of a whole ref names, where no index file's or root's does.
const SearchCacheRefPath = "/"

// Whether a part derives from one kept index file, which must be held, and whether it is one at all.
func searchCachePartOfFile(part SearchCachePart) (ofFile bool, known bool) {
	switch part {
	case SearchCachePartBlockIndex, SearchCachePartDocCounts:
		return true, true
	case SearchCachePartFile, SearchCachePartManifest, SearchCachePartVersionTable, SearchCachePartLocalLayer,
		SearchCachePartMismatch, SearchCachePartVocabulary:
		return false, true
	}
	return false, false
}

// Derived data offered to the cache.
type SearchCacheDerived struct {
	Key  SearchCacheKey
	Part SearchCachePart
	// The plaintext, sealed under the local search key in 64 KiB frames.
	Plaintext []byte
	// SearchCachePartFile: the entry version's content_sha256, which the plaintext must hash to, and its partition.
	ContentSha256 [sha256.Size]byte
	Partition     SearchCachePartition
}

// Keeps derived data (§5.9's holds row): a reproduced file only once its SHA-256 is its entry version's
// content_sha256, which then counts as held as a record does; a file's block index or n_d array only while the file is
// held; a ref's or root's part of a ref this cache follows. Anything else is ErrSearchCacheUnnamed, and nothing is
// written. The cache's bound then applies.
func (self *SearchCache) PutDerived(ctx context.Context, derived *SearchCacheDerived) error {
	if derived == nil {
		return ErrSearchCacheArgs
	}
	if err := derived.Key.check(); err != nil {
		return err
	}
	ofFile, known := searchCachePartOfFile(derived.Part)
	if !known {
		return fmt.Errorf("%w: no derived part %q", ErrSearchCacheUnnamed, derived.Part)
	}
	if derived.Part == SearchCachePartFile && sha256.Sum256(derived.Plaintext) != derived.ContentSha256 {
		return ErrSearchCacheContent
	}
	if err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		ref, err := self.loadRefWithLock(derived.Key.RepoId, derived.Key.RefId)
		if err != nil {
			return err
		}
		held := false
		followed := false
		func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			followed = ref.RefVersion != 0 || 0 < len(ref.Files)
			for _, file := range ref.Files {
				if file.Key == derived.Key {
					held = true
				}
			}
		}()
		switch {
		case ofFile && !held:
			return fmt.Errorf("%w: the cache does not hold that file", ErrSearchCacheUnnamed)
		case derived.Part != SearchCachePartFile && !followed:
			return fmt.Errorf("%w: the cache follows no such ref", ErrSearchCacheUnnamed)
		}
		frames := searchCacheSplitFrames(derived.Plaintext)
		plaintextSum := sha256.Sum256(derived.Plaintext)
		byteCount, err := self.writeFramed(searchCachePartName(derived.Key, string(derived.Part)), frames, &searchCacheMetaWire{
			Length:     int64(len(derived.Plaintext)),
			FrameCount: len(frames),
			Sha256:     hex.EncodeToString(plaintextSum[:]),
		})
		if err != nil {
			return err
		}
		self.decoded.dropPrefix(searchCachePartName(derived.Key, string(derived.Part)))
		if derived.Part != SearchCachePartFile {
			return nil
		}
		self.keepFileWithLock(ref, SearchCacheFile{
			Key:           derived.Key,
			ContentSha256: derived.ContentSha256,
			Partition:     derived.Partition,
			Kind:          searchCacheKindFile,
			ByteCount:     byteCount,
			KeptAt:        self.clock.Now(),
		})
		return self.storeRefWithLock(ref)
	}(); err != nil {
		return err
	}
	_, err := self.Evict()
	return err
}

// plaintext in 64 KiB frames, at least one.
func searchCacheSplitFrames(plaintext []byte) [][]byte {
	frames := [][]byte{}
	for start := 0; start < len(plaintext) || len(frames) == 0; start += EvsRecordFrameByteCount {
		frames = append(frames, plaintext[start:min(len(plaintext), start+EvsRecordFrameByteCount)])
	}
	return frames
}

// Kept derived data, read a frame at a time: a frame source for the index's readers too.
type SearchCacheFrames struct {
	cache *SearchCache
	key   SearchCacheKey
	base  string
	meta  *searchCacheMetaWire
}

// The derived part at key, or ErrSidecarStoreAbsent; ErrSearchCacheRefetch for one that failed and was dropped.
func (self *SearchCache) OpenDerived(key SearchCacheKey, part SearchCachePart) (*SearchCacheFrames, error) {
	if err := key.check(); err != nil {
		return nil, err
	}
	if _, known := searchCachePartOfFile(part); !known {
		return nil, fmt.Errorf("%w: no derived part %q", ErrSearchCacheUnnamed, part)
	}
	base := searchCachePartName(key, string(part))
	meta, err := self.readMeta(base)
	if err != nil {
		if errors.Is(err, ErrSidecarStoreAbsent) {
			return nil, ErrSidecarStoreAbsent
		}
		return nil, self.derivedFailed(key, part, err)
	}
	return &SearchCacheFrames{cache: self, key: key, base: base, meta: meta}, nil
}

// The plaintext's length.
func (self *SearchCacheFrames) Length() int64 {
	return self.meta.Length
}

// The frame count.
func (self *SearchCacheFrames) FrameCount() int {
	return self.meta.FrameCount
}

// Frame index's plaintext: one sealed file opened, one frame decrypted. A frame that fails drops the part, and a
// reproduced file's whole file: ErrSearchCacheRefetch.
func (self *SearchCacheFrames) ReadFrame(index int) ([]byte, error) {
	if index < 0 || self.meta.FrameCount <= index {
		return nil, fmt.Errorf("%w: a frame past the part", ErrSearchCacheArgs)
	}
	frame, err := self.cache.readSmall(self.base+"/"+strconv.Itoa(index), EvsRecordFrameByteCount)
	if err != nil {
		return nil, self.cache.derivedFailed(self.key, SearchCachePart(self.base[strings.LastIndexByte(self.base, '/')+1:]), err)
	}
	want := min(int64(EvsRecordFrameByteCount), self.meta.Length-int64(index)*EvsRecordFrameByteCount)
	if int64(len(frame)) != max(want, 0) {
		return nil, self.cache.derivedFailed(self.key, SearchCachePart(self.base[strings.LastIndexByte(self.base, '/')+1:]), ErrSidecarStoreFailed)
	}
	return frame, nil
}

// The whole plaintext, frame by frame, checked against the SHA-256 kept with it: for parts small enough to hold.
func (self *SearchCacheFrames) ReadAll() ([]byte, error) {
	whole := make([]byte, 0, self.meta.Length)
	for index := 0; index < self.meta.FrameCount; index += 1 {
		frame, err := self.ReadFrame(index)
		if err != nil {
			return nil, err
		}
		whole = append(whole, frame...)
	}
	sum := sha256.Sum256(whole)
	if hex.EncodeToString(sum[:]) != self.meta.Sha256 {
		return nil, self.cache.derivedFailed(self.key, SearchCachePart(self.base[strings.LastIndexByte(self.base, '/')+1:]), ErrSidecarStoreFailed)
	}
	return whole, nil
}

// The plaintext's length, for the index's readers.
func (self *SearchCacheFrames) indexLength() int {
	return int(self.meta.Length)
}

// Frame index's plaintext, for the index's readers; dst goes unused, since each frame is its own file.
func (self *SearchCacheFrames) indexReadFrame(index int, dst []byte) ([]byte, error) {
	return self.ReadFrame(index)
}

// A derived part's read failed: one that failed AEAD or decoding, or lost a frame, is dropped, with the whole file for a
// reproduced one, and answered ErrSearchCacheRefetch; a lock is answered as it is.
func (self *SearchCache) derivedFailed(key SearchCacheKey, part SearchCachePart, err error) error {
	if part == SearchCachePartFile {
		return self.readFailed(key, err)
	}
	if !isSearchCacheDamage(err) {
		return err
	}
	self.log.Warningf("[search]a derived part failed: dropped, to derive again")
	if dropErr := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		return self.removeUnder(searchCachePartName(key, string(part)))
	}(); dropErr != nil {
		return dropErr
	}
	return ErrSearchCacheRefetch
}

// The decoded state's key: a part's store name and what a reader decoded from it.
type SearchDecodedKey struct {
	Key  SearchCacheKey
	Part string
	// what was decoded: a frame's index, a block's, a table's
	Item uint64
}

// The name the LRU keeps a decoded entry under, which a file's removal drops by prefix.
func (self SearchDecodedKey) name() string {
	return searchCachePartName(self.Key, self.Part) + "#" + strconv.FormatUint(self.Item, 10)
}

// A reader's decoded index state: the value under key, decoding it with decode on a miss, kept in the LRU within
// Search.MemoryByteCount while decode's byte count fits (§5.9's bounds row).
func (self *SearchCache) Decoded(key SearchDecodedKey, decode func() (any, int64, error)) (any, error) {
	return self.decoded.get(key.name(), decode)
}

// A version-table page, CORE-M10-02's, in its own LRU within Search.VersionCacheByteCount.
func (self *SearchCache) VersionPage(key SearchDecodedKey, decode func() (any, int64, error)) (any, error) {
	return self.versionPages.get(key.name(), decode)
}

// An LRU of decoded values within a byte bound.
type searchDecodedCache struct {
	maxByteCount int64

	stateLock sync.Mutex
	byteCount int64
	order     *list.List
	entries   map[string]*list.Element
}

// One decoded value.
type searchDecodedEntry struct {
	name      string
	value     any
	byteCount int64
}

// An empty LRU holding at most maxByteCount.
func newSearchDecodedCache(maxByteCount int64) *searchDecodedCache {
	return &searchDecodedCache{maxByteCount: maxByteCount, order: list.New(), entries: map[string]*list.Element{}}
}

// The value under name, decoded on a miss, outside the lock; a value larger than the bound is answered and not kept.
func (self *searchDecodedCache) get(name string, decode func() (any, int64, error)) (any, error) {
	if value, ok := self.lookup(name); ok {
		return value, nil
	}
	value, byteCount, err := decode()
	if err != nil {
		return nil, err
	}
	self.put(name, value, byteCount)
	return value, nil
}

// The value under name, if held, made the most recently used.
func (self *searchDecodedCache) lookup(name string) (any, bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	element, ok := self.entries[name]
	if !ok {
		return nil, false
	}
	self.order.MoveToFront(element)
	return element.Value.(*searchDecodedEntry).value, true
}

// Keeps value under name, the least recently used going until the bound holds.
func (self *searchDecodedCache) put(name string, value any, byteCount int64) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if byteCount < 0 || self.maxByteCount < byteCount {
		return
	}
	if element, ok := self.entries[name]; ok {
		self.byteCount -= element.Value.(*searchDecodedEntry).byteCount
		self.order.Remove(element)
		delete(self.entries, name)
	}
	self.entries[name] = self.order.PushFront(&searchDecodedEntry{name: name, value: value, byteCount: byteCount})
	self.byteCount += byteCount
	for self.maxByteCount < self.byteCount {
		oldest := self.order.Back()
		entry := oldest.Value.(*searchDecodedEntry)
		self.order.Remove(oldest)
		delete(self.entries, entry.name)
		self.byteCount -= entry.byteCount
	}
}

// What the LRU holds, in bytes.
func (self *searchDecodedCache) heldByteCount() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.byteCount
}

// Drops every value.
func (self *searchDecodedCache) drop() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.order.Init()
	clear(self.entries)
	self.byteCount = 0
}

// Drops every value whose name starts with prefix.
func (self *searchDecodedCache) dropPrefix(prefix string) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for name, element := range self.entries {
		if strings.HasPrefix(name, prefix) {
			self.byteCount -= element.Value.(*searchDecodedEntry).byteCount
			self.order.Remove(element)
			delete(self.entries, name)
		}
	}
}

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
