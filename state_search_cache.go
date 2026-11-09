// §5.9's index cache (CORE-M10-01; R-CORE-18, D-CORE-16, I-19, FI-23): one network's sealed store of the search index
// files this device keeps and their derived data, under file class search, which §11.14's read path, §16.10's search
// and remote serving read and nothing else writes. 9.9's track owns the formats and the engine, which call this store;
// this file keeps what the store holds, how a record is checked before it is kept, and how a kept file reads back.
//
// Per indexed ref this device follows it holds the ref version it verified (§11.9) and each index file it keeps, as the
// sealed evs record it fetched under the repo's object keys, kept only once its plaintext's SHA-256 equals its entry
// version's content_sha256, which is checked by opening every frame here before anything is written: a file no verified
// entry version named is never kept. A mirror of the ref shares these copies. The record's frames stay sealed as evs
// sealed them, and each is kept as its own file of the store, so a reader opens one 64 KiB frame at a time, by index,
// under keys the cache never holds (searchRecordFrames). Derived data is state_search_derived.go's.
//
// The store's layout under net/<network_id>/search/, every file sealed under HKDF(R_n, "urnetwork-sidecar-v1/local/search")
// with XChaCha20-Poly1305 and a random nonce prefix, its name in the AAD (state_seal.go):
//
//	<repo>/<ref>/holdings                           the ref's record: its verified version, its files, retained buckets
//	<repo>/<ref>/p<hex path>/<version>/<part>/m     one kept file's meta, written last: its commit point
//	<repo>/<ref>/p<hex path>/<version>/<part>/<i>   its frame i
//
// so a file's AAD is repo || ref || path || version || part (§5.9's holds row), with the frame index after. part is
// "record" for an evs record, else a derived part. Ids are lowercase hex, the path hex so every path is one segment.
//
// Never stored (R-CORE-18, owner decision 175): a query, query history, hit, snippet, cursor, result count or
// per-query verdict. No call here takes one: derived parts are a closed list, and when a partition was last searched is
// kept in memory only, for eviction's order, never on the medium. A kept file that fails AEAD or decoding is dropped and
// answered ErrSearchCacheRefetch, since everything here is derived and refetchable, unlike the keychain, where such a
// failure is Failed (§5.9's rebuild row). Locked drops the decoded state and open cursors (state_search_derived.go).
//
// Bounds, eviction and retained buckets are state_search_bounds.go's. Search.CacheByteCount 0 keeps the whole cache in
// memory, for ephemeral sidecars, writing nothing to the medium. Browsers' Store is the host's IndexedDB backend.
//
// On every leg: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// §5.9's file class of the index cache and search state, and the cache's directory.
const (
	SidecarSearchFileClass  = "search"
	sidecarSearchCacheDir   = "search"
	searchCacheHoldingsName = "holdings"
	searchCacheMetaName     = "m"
	searchCachePartRecord   = "record"
	searchCacheHoldingsMax  = 16 * 1024 * 1024
	searchCacheMetaMax      = 64 * 1024
	searchCacheFrameMax     = EvsRecordFrameByteCount + chacha20poly1305.Overhead
	searchCacheHoldingsVer  = 1
)

var (
	// A record whose plaintext's SHA-256 is not its entry version's content_sha256, or whose frames do not open: nothing
	// is kept.
	ErrSearchCacheContent = errors.New("search cache: the file is not its entry version's content")
	// A kept file failed AEAD or decoding, or went missing in part: it is dropped, and the caller fetches it again.
	ErrSearchCacheRefetch = errors.New("search cache: the kept file was dropped; fetch it again")
	// Derived data for a file this cache does not hold, or a part no derived data is.
	ErrSearchCacheUnnamed = errors.New("search cache: no verified entry version names it")
	// What a call asks of the cache is not well formed.
	ErrSearchCacheArgs = errors.New("search cache: invalid arguments")
)

// One index file version a ref's index names: its path under the index root and its entry version.
type SearchCacheKey struct {
	RepoId Id
	RefId  Id
	Path   string
	// The path's entry version (§11.7).
	Version uint64
}

// The partition an index file belongs to: all, or the bucket starting on StartDay.
type SearchCachePartition struct {
	All      bool
	StartDay uint32
}

// An index file's record as fetched, offered to the cache: kept only once its frames open and its plaintext's SHA-256
// equals ContentSha256.
type SearchCacheRecord struct {
	Key SearchCacheKey
	// The ref version whose verified listing names this entry version (§11.9).
	RefVersion uint64
	// The entry version's content_sha256 (§11.7).
	ContentSha256 [sha256.Size]byte
	Partition     SearchCachePartition
	// The record as evs sealed it: its 160 B sealed header, which is kept, and its sealed frames.
	SealedHeader []byte
	SealedFrames []byte
	// What opens it for the check, from the evs read path, which the cache never keeps: the header opened under its
	// manifest key, the object key it names, and the record's file id, its frames' AAD.
	Header    *EvsRecordHeader
	ObjectKey *EvsObjectKey
	FileId    Id
}

// One file the cache keeps, as the holdings record lists it.
type SearchCacheFile struct {
	Key           SearchCacheKey
	ContentSha256 [sha256.Size]byte
	Partition     SearchCachePartition
	// record: the evs record as fetched; file: a reproduced file's plaintext, sealed locally (state_search_derived.go).
	Kind string
	// What it takes in the store.
	ByteCount int64
	KeptAt    time.Time
}

// What the cache holds of one ref.
type SearchCacheRef struct {
	RepoId Id
	RefId  Id
	// The ref version this device verified (§11.9); 0 before one.
	RefVersion uint64
	Files      []SearchCacheFile
	// Buckets a roll-up dropped, kept while a stale all is cached (state_search_bounds.go).
	Retained []SearchCacheRetained
}

// The holdings record's encoding, sealed in the store.
type searchCacheHoldingsWire struct {
	Version    int                       `json:"version"`
	RefVersion uint64                    `json:"ref_version"`
	Files      []searchCacheFileWire     `json:"files"`
	Retained   []searchCacheRetainedWire `json:"retained,omitempty"`
}

// One file of the holdings record.
type searchCacheFileWire struct {
	Path     string `json:"path"`
	Version  uint64 `json:"version"`
	Sha256   string `json:"sha256"`
	All      bool   `json:"all,omitempty"`
	StartDay uint32 `json:"start_day,omitempty"`
	Kind     string `json:"kind"`
	Bytes    int64  `json:"bytes"`
	KeptMs   int64  `json:"kept_ms"`
}

// A kept file's meta: its frames and, for a record, its sealed header.
type searchCacheMetaWire struct {
	Length       int64  `json:"length"`
	FrameCount   int    `json:"frames"`
	SealedHeader []byte `json:"header,omitempty"`
	Sha256       string `json:"sha256,omitempty"`
}

// The index cache. Construct with NewSearchCache.
type SearchCache struct {
	store    SidecarStore
	settings *SidecarSearchSettings
	clock    Clock
	log      Logger
	// whether the cache lives in memory (Search.CacheByteCount 0)
	memory bool
	cancel context.CancelFunc
	done   chan struct{}
	// decoded index state, within Search.MemoryByteCount, and version-table pages within VersionCacheByteCount
	decoded      *searchDecodedCache
	versionPages *searchDecodedCache

	// one mutation at a time: a put, a removal, an eviction
	operationLock sync.Mutex

	stateLock sync.Mutex
	// each followed ref's holdings, loaded on first use
	refs map[[2]Id]*SearchCacheRef
	// what the store holds in all, its bound's measure
	byteCount int64
	// when each (ref, partition kind) was last searched: memory only, for eviction's order
	searched map[searchCacheSearchedKey]time.Time
	// whether this daemon is designated for search, and the repos it serves, whose all it keeps longest (D-CORE-17)
	designated bool
	served     map[Id]bool
	// open cursors, which Locked ends
	cursors      map[uint64]func()
	nextCursorId uint64
}

// A ref's partition kind, for when it was last searched.
type searchCacheSearchedKey struct {
	repoId Id
	refId  Id
	all    bool
}

// A cache over store, a SidecarInstance's store for one network, under settings: its files in store's search/
// directory, sealed under file class search, or in memory when settings.CacheByteCount is 0. When store is a
// SidecarInstance's, a lock of the instance drops the decoded state and open cursors, until ctx ends or Close.
func NewSearchCache(ctx context.Context, store SidecarStore, settings *SidecarSearchSettings, clock Clock, log Logger) (*SearchCache, error) {
	if settings == nil || store == nil {
		return nil, fmt.Errorf("%w: a search cache needs its store and settings", ErrSearchCacheArgs)
	}
	if settings.CacheByteCount < 0 || settings.MemoryByteCount <= 0 || settings.VersionCacheByteCount <= 0 ||
		settings.MemoryByteCount < settings.VersionCacheByteCount {
		return nil, fmt.Errorf("%w: the search settings' bounds", ErrSearchCacheArgs)
	}
	self := &SearchCache{
		settings:     settings,
		clock:        clockOrReal(clock),
		log:          loggerOrDefault(log),
		memory:       settings.CacheByteCount == 0,
		decoded:      newSearchDecodedCache(settings.MemoryByteCount - settings.VersionCacheByteCount),
		versionPages: newSearchDecodedCache(settings.VersionCacheByteCount),
		refs:         map[[2]Id]*SearchCacheRef{},
		searched:     map[searchCacheSearchedKey]time.Time{},
		served:       map[Id]bool{},
		cursors:      map[uint64]func(){},
		done:         make(chan struct{}),
	}
	if self.memory {
		// an ephemeral sidecar's cache: nothing reaches the medium (§5.9's bounds row)
		self.store = newSearchMemoryStore()
	} else {
		cacheStore, err := store.Directory(sidecarSearchCacheDir, SidecarSearchFileClass)
		if err != nil {
			return nil, err
		}
		self.store = cacheStore
		entries, err := cacheStore.List("")
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			self.byteCount += entry.ByteCount
		}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	self.cancel = cancel
	instance, _, ok := sidecarInstanceOfStore(store)
	if !ok {
		close(self.done)
		return self, nil
	}
	go self.watchLock(watchCtx, instance)
	return self, nil
}

// Drops the decoded state and ends every open cursor each time the instance leaves Open (§5.9's delete row), until ctx
// ends.
func (self *SearchCache) watchLock(ctx context.Context, instance *SidecarInstance) {
	defer close(self.done)
	for {
		state, changed := instance.State()
		if state != SidecarInstanceOpen {
			self.Locked()
		}
		select {
		case <-ctx.Done():
			return
		case <-changed:
		}
	}
}

// Stops watching the instance. The files stay.
func (self *SearchCache) Close() {
	self.cancel()
	<-self.done
	self.Locked()
}

// What a lock does to the cache: the decoded state goes, and every open cursor ends (§5.9's delete row). The files
// stay, sealed.
func (self *SearchCache) Locked() {
	self.decoded.drop()
	self.versionPages.drop()
	cursors := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cursors := make([]func(), 0, len(self.cursors))
		for _, end := range self.cursors {
			cursors = append(cursors, end)
		}
		clear(self.cursors)
		return cursors
	}()
	for _, end := range cursors {
		end()
	}
}

// Registers an open cursor, which a lock ends by calling end. The answer removes it, as its search closes it. A cursor
// lives in memory only (§5.9's never row).
func (self *SearchCache) AddCursor(end func()) func() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.nextCursorId += 1
	cursorId := self.nextCursorId
	self.cursors[cursorId] = end
	var once sync.Once
	return func() {
		once.Do(func() {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			delete(self.cursors, cursorId)
		})
	}
}

// What the store holds in all.
func (self *SearchCache) ByteCount() int64 {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.byteCount
}

// The store name of a ref's directory, and of a file's part under it.
func searchCacheRefName(repoId Id, refId Id) string {
	return hex.EncodeToString(repoId[:]) + "/" + hex.EncodeToString(refId[:])
}

// The store name of one part of a kept file: its directory, under which its meta and frames sit.
func searchCachePartName(key SearchCacheKey, part string) string {
	return searchCacheRefName(key.RepoId, key.RefId) + "/p" + hex.EncodeToString([]byte(key.Path)) + "/" +
		strconv.FormatUint(key.Version, 10) + "/" + part
}

// A key the cache takes: ids set, a path that is not empty and holds no NUL.
func (self SearchCacheKey) check() error {
	if self.RepoId == (Id{}) || self.RefId == (Id{}) || self.Path == "" || strings.IndexByte(self.Path, 0) != -1 {
		return fmt.Errorf("%w: a file key", ErrSearchCacheArgs)
	}
	return nil
}

// A ref's holdings, loaded on first use: nil and no error for a ref the cache holds nothing of.
func (self *SearchCache) loadRefWithLock(repoId Id, refId Id) (*SearchCacheRef, error) {
	self.stateLock.Lock()
	ref, ok := self.refs[[2]Id{repoId, refId}]
	self.stateLock.Unlock()
	if ok {
		return ref, nil
	}
	ref = &SearchCacheRef{RepoId: repoId, RefId: refId}
	content, err := self.readSmall(searchCacheRefName(repoId, refId)+"/"+searchCacheHoldingsName, searchCacheHoldingsMax)
	switch {
	case err == nil:
		wire := &searchCacheHoldingsWire{}
		if json.Unmarshal(content, wire) != nil || wire.Version != searchCacheHoldingsVer {
			// derived state: dropped whole and refetched (§5.9's rebuild row)
			self.log.Warningf("[search]a ref's cache record did not decode: dropped")
			if err := self.dropRefFilesWithLock(repoId, refId); err != nil {
				return nil, err
			}
			break
		}
		ref.RefVersion = wire.RefVersion
		for _, file := range wire.Files {
			sum, err := hex.DecodeString(file.Sha256)
			if err != nil || len(sum) != sha256.Size {
				continue
			}
			kept := SearchCacheFile{
				Key:       SearchCacheKey{RepoId: repoId, RefId: refId, Path: file.Path, Version: file.Version},
				Partition: SearchCachePartition{All: file.All, StartDay: file.StartDay},
				Kind:      file.Kind,
				ByteCount: file.Bytes,
				KeptAt:    time.UnixMilli(file.KeptMs),
			}
			copy(kept.ContentSha256[:], sum)
			ref.Files = append(ref.Files, kept)
		}
		for _, retained := range wire.Retained {
			ref.Retained = append(ref.Retained, retained.retained())
		}
	case errors.Is(err, ErrSidecarStoreAbsent):
	case errors.Is(err, ErrSidecarStoreFailed):
		self.log.Warningf("[search]a ref's cache record failed: dropped")
		if err := self.dropRefFilesWithLock(repoId, refId); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.refs[[2]Id{repoId, refId}] = ref
	return ref, nil
}

// Writes a ref's holdings record, or removes it once the ref holds nothing.
func (self *SearchCache) storeRefWithLock(ref *SearchCacheRef) error {
	name := searchCacheRefName(ref.RepoId, ref.RefId) + "/" + searchCacheHoldingsName
	if ref.RefVersion == 0 && len(ref.Files) == 0 && len(ref.Retained) == 0 {
		return self.removeCounted(name)
	}
	wire := &searchCacheHoldingsWire{Version: searchCacheHoldingsVer, RefVersion: ref.RefVersion}
	for _, file := range ref.Files {
		wire.Files = append(wire.Files, searchCacheFileWire{
			Path:     file.Key.Path,
			Version:  file.Key.Version,
			Sha256:   hex.EncodeToString(file.ContentSha256[:]),
			All:      file.Partition.All,
			StartDay: file.Partition.StartDay,
			Kind:     file.Kind,
			Bytes:    file.ByteCount,
			KeptMs:   file.KeptAt.UnixMilli(),
		})
	}
	for _, retained := range ref.Retained {
		wire.Retained = append(wire.Retained, retainedWireOf(retained))
	}
	encoded, err := json.Marshal(wire)
	if err != nil {
		return err
	}
	return self.writeSmall(name, encoded, true)
}

// A small sealed file's plaintext, at most maxByteCount.
func (self *SearchCache) readSmall(name string, maxByteCount int) ([]byte, error) {
	reader, err := self.store.Open(name)
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, int64(maxByteCount)+1))
	if err != nil {
		return nil, err
	}
	if maxByteCount < len(content) {
		return nil, fmt.Errorf("%w: a cache file past its bound", ErrSidecarStoreFailed)
	}
	return content, nil
}

// Writes a small sealed file, counting the bytes it takes: replacing one that may be there, whose bytes it then stops
// counting, or a new one in a directory just cleared.
func (self *SearchCache) writeSmall(name string, content []byte, replacing bool) error {
	before := int64(0)
	if replacing {
		before = self.storedByteCount(name)
	}
	writer, err := self.store.Create(name)
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(content); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	after := self.storedByteCount(name)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.byteCount += after - before
	return nil
}

// What one name takes in the store now, 0 for none.
func (self *SearchCache) storedByteCount(name string) int64 {
	entries, err := self.store.List(name)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if entry.Name == name {
			return entry.ByteCount
		}
	}
	return 0
}

// Removes one name, counting the bytes it frees.
func (self *SearchCache) removeCounted(name string) error {
	return self.removeSized(name, self.storedByteCount(name))
}

// Removes one name of byteCount bytes.
func (self *SearchCache) removeSized(name string, byteCount int64) error {
	if err := self.store.Remove(name); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.byteCount -= byteCount
	return nil
}

// Every file under prefix, a ref's or a file's directory, each named from the store's directory.
func (self *SearchCache) namesUnder(prefix string) ([]SidecarStoreEntry, error) {
	return self.store.List(prefix + "/")
}

// Removes every name under prefix, meta first so a reader never takes a part for whole, yielding between files.
func (self *SearchCache) removeUnder(prefix string) error {
	entries, err := self.namesUnder(prefix)
	if err != nil {
		return err
	}
	slices.SortStableFunc(entries, func(a SidecarStoreEntry, b SidecarStoreEntry) int {
		aMeta := strings.HasSuffix(a.Name, "/"+searchCacheMetaName)
		bMeta := strings.HasSuffix(b.Name, "/"+searchCacheMetaName)
		switch {
		case aMeta && !bMeta:
			return -1
		case bMeta && !aMeta:
			return 1
		}
		return 0
	})
	yield := newSidecarYield(self.clock)
	for _, entry := range entries {
		// a listing names each file from the store's directory, the prefix included
		if err := self.removeSized(entry.Name, entry.ByteCount); err != nil {
			return err
		}
		yield.step()
	}
	return nil
}

// Drops every file of a ref from the store, with its holdings record.
func (self *SearchCache) dropRefFilesWithLock(repoId Id, refId Id) error {
	if err := self.removeUnder(searchCacheRefName(repoId, refId)); err != nil {
		return err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	delete(self.refs, [2]Id{repoId, refId})
	return nil
}

// Writes a kept file's frames, then its meta, the commit point; a part written before replaces nothing until then.
func (self *SearchCache) writeFramed(base string, frames [][]byte, meta *searchCacheMetaWire) (int64, error) {
	// an earlier copy goes first, meta first, so no reader takes old and new frames for one file
	if err := self.removeUnder(base); err != nil {
		return 0, err
	}
	var byteCount int64
	yield := newSidecarYield(self.clock)
	for index, frame := range frames {
		if err := self.writeSmall(base+"/"+strconv.Itoa(index), frame, false); err != nil {
			return 0, err
		}
		yield.step()
	}
	encoded, err := json.Marshal(meta)
	if err != nil {
		return 0, err
	}
	if err := self.writeSmall(base+"/"+searchCacheMetaName, encoded, false); err != nil {
		return 0, err
	}
	entries, err := self.namesUnder(base)
	if err != nil {
		return 0, err
	}
	for _, entry := range entries {
		byteCount += entry.ByteCount
	}
	return byteCount, nil
}

// A kept file's meta, or ErrSidecarStoreAbsent.
func (self *SearchCache) readMeta(base string) (*searchCacheMetaWire, error) {
	content, err := self.readSmall(base+"/"+searchCacheMetaName, searchCacheMetaMax)
	if err != nil {
		return nil, err
	}
	meta := &searchCacheMetaWire{}
	if json.Unmarshal(content, meta) != nil || meta.Length < 0 || meta.FrameCount < 0 {
		return nil, fmt.Errorf("%w: a cache file's meta", ErrSidecarStoreFailed)
	}
	return meta, nil
}

// Opens each of a record's sealed frames under keys, hashing the plaintext, which is cleared as it goes: the check
// before a record is kept. Answers the sealed frames, split.
func searchCacheCheckRecord(record *SearchCacheRecord) ([][]byte, error) {
	header := record.Header
	if header == nil || record.ObjectKey == nil || len(record.SealedHeader) != EvsRecordHeaderByteCount {
		return nil, fmt.Errorf("%w: a record without its header or key", ErrSearchCacheArgs)
	}
	if uint64(len(record.SealedFrames)) != EvsRecordByteCount(header.BodyLength)-EvsRecordHeaderByteCount {
		return nil, fmt.Errorf("%w: its frames are not its header's length", ErrSearchCacheContent)
	}
	frames := &evsRecordFrames{}
	if err := frames.begin(record.ObjectKey, record.Key.RepoId, record.FileId, header); err != nil {
		return nil, err
	}
	hash := sha256.New()
	split := make([][]byte, 0, frames.frameCount)
	remaining := header.BodyLength
	at := 0
	plaintext := make([]byte, 0, EvsRecordFrameByteCount)
	defer clear(plaintext[:cap(plaintext)])
	for frames.frameIndex = 0; uint64(frames.frameIndex) < frames.frameCount; frames.frameIndex += 1 {
		length := int(min(uint64(EvsRecordFrameByteCount), remaining)) + chacha20poly1305.Overhead
		sealed := record.SealedFrames[at : at+length]
		frames.frame()
		opened, err := frames.aead.Open(plaintext[:0], frames.nonce[:], sealed, frames.aad[:])
		if err != nil {
			return nil, fmt.Errorf("%w: frame %d does not open", ErrSearchCacheContent, frames.frameIndex)
		}
		hash.Write(opened)
		clear(opened)
		split = append(split, bytes.Clone(sealed))
		remaining -= uint64(length - chacha20poly1305.Overhead)
		at += length
	}
	if !bytes.Equal(hash.Sum(nil), record.ContentSha256[:]) {
		return nil, ErrSearchCacheContent
	}
	return split, nil
}

// Keeps an index file's record (§5.9's holds row), once every frame opens under the record's keys and the plaintext's
// SHA-256 equals its entry version's content_sha256; else nothing is written and the answer is ErrSearchCacheContent.
// The record's frames are kept as evs sealed them. A copy kept before at the same key is replaced. The cache's bound
// then applies (Evict).
func (self *SearchCache) PutRecord(ctx context.Context, record *SearchCacheRecord) error {
	if record == nil {
		return ErrSearchCacheArgs
	}
	if err := record.Key.check(); err != nil {
		return err
	}
	frames, err := searchCacheCheckRecord(record)
	if err != nil {
		return err
	}
	if err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		ref, err := self.loadRefWithLock(record.Key.RepoId, record.Key.RefId)
		if err != nil {
			return err
		}
		byteCount, err := self.writeFramed(searchCachePartName(record.Key, searchCachePartRecord), frames, &searchCacheMetaWire{
			Length:       int64(record.Header.BodyLength),
			FrameCount:   len(frames),
			SealedHeader: bytes.Clone(record.SealedHeader),
			Sha256:       hex.EncodeToString(record.ContentSha256[:]),
		})
		if err != nil {
			return err
		}
		self.keepFileWithLock(ref, SearchCacheFile{
			Key:           record.Key,
			ContentSha256: record.ContentSha256,
			Partition:     record.Partition,
			Kind:          searchCacheKindRecord,
			ByteCount:     byteCount,
			KeptAt:        self.clock.Now(),
		})
		if ref.RefVersion < record.RefVersion {
			ref.RefVersion = record.RefVersion
		}
		return self.storeRefWithLock(ref)
	}(); err != nil {
		return err
	}
	_, err = self.Evict()
	return err
}

// The kinds a kept file is.
const (
	searchCacheKindRecord = "record"
	searchCacheKindFile   = "file"
)

// Lists file in ref's holdings, replacing the entry for its key.
func (self *SearchCache) keepFileWithLock(ref *SearchCacheRef, file SearchCacheFile) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	ref.Files = slices.DeleteFunc(ref.Files, func(kept SearchCacheFile) bool { return kept.Key == file.Key })
	ref.Files = append(ref.Files, file)
}

// The kept file at key, if the holdings list it.
func (self *SearchCache) heldFile(key SearchCacheKey) (SearchCacheFile, bool, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	ref, err := self.loadRefWithLock(key.RepoId, key.RefId)
	if err != nil {
		return SearchCacheFile{}, false, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, file := range ref.Files {
		if file.Key == key {
			return file, true, nil
		}
	}
	return SearchCacheFile{}, false, nil
}

// Records the ref version this device verified for a ref it follows (§11.9). It never falls.
func (self *SearchCache) SetRefVersion(repoId Id, refId Id, refVersion uint64) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	ref, err := self.loadRefWithLock(repoId, refId)
	if err != nil {
		return err
	}
	if refVersion <= ref.RefVersion {
		return nil
	}
	ref.RefVersion = refVersion
	return self.storeRefWithLock(ref)
}

// What the cache holds of a ref, a copy: nil for a ref it holds nothing of.
func (self *SearchCache) Ref(repoId Id, refId Id) (*SearchCacheRef, error) {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	ref, err := self.loadRefWithLock(repoId, refId)
	if err != nil {
		return nil, err
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if ref.RefVersion == 0 && len(ref.Files) == 0 && len(ref.Retained) == 0 {
		return nil, nil
	}
	copied := *ref
	copied.Files = slices.Clone(ref.Files)
	copied.Retained = slices.Clone(ref.Retained)
	return &copied, nil
}

// Takes a kept file away, its derived data with it.
func (self *SearchCache) Remove(key SearchCacheKey) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	return self.removeFileWithLock(key)
}

// Removes a kept file's record or reproduced copy and every derived part of it, and its holdings entry.
func (self *SearchCache) removeFileWithLock(key SearchCacheKey) error {
	ref, err := self.loadRefWithLock(key.RepoId, key.RefId)
	if err != nil {
		return err
	}
	fileDir := searchCacheRefName(key.RepoId, key.RefId) + "/p" + hex.EncodeToString([]byte(key.Path)) + "/" +
		strconv.FormatUint(key.Version, 10)
	if err := self.removeUnder(fileDir); err != nil {
		return err
	}
	self.decoded.dropPrefix(fileDir)
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		ref.Files = slices.DeleteFunc(ref.Files, func(kept SearchCacheFile) bool { return kept.Key == key })
	}()
	return self.storeRefWithLock(ref)
}

// Drops everything the cache holds of a ref: `ur search sync --evict`, and CORE-M10-04's deletions build on it.
func (self *SearchCache) DropRef(repoId Id, refId Id) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	if err := self.dropRefFilesWithLock(repoId, refId); err != nil {
		return err
	}
	self.decoded.dropPrefix(searchCacheRefName(repoId, refId))
	return nil
}

// Drops everything the cache holds of a repo, every ref of it.
func (self *SearchCache) DropRepo(repoId Id) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	prefix := hex.EncodeToString(repoId[:])
	if err := self.removeUnder(prefix); err != nil {
		return err
	}
	self.decoded.dropPrefix(prefix)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for key := range self.refs {
		if key[0] == repoId {
			delete(self.refs, key)
		}
	}
	return nil
}

// A kept record's frames, read one at a time (§5.9's bounds row): the sealed header as fetched, which the reader opens
// under its manifest key, and each frame, opened under the object key it names, so one 64 KiB frame is decrypted at a
// time and nothing of the record is decrypted at rest.
type SearchCacheRecordFrames struct {
	cache *SearchCache
	key   SearchCacheKey
	base  string
	meta  *searchCacheMetaWire
}

// The kept record at key, or ErrSidecarStoreAbsent for one the cache does not hold; ErrSearchCacheRefetch for one that
// failed and was dropped.
func (self *SearchCache) OpenRecord(key SearchCacheKey) (*SearchCacheRecordFrames, error) {
	if err := key.check(); err != nil {
		return nil, err
	}
	file, ok, err := self.heldFile(key)
	if err != nil {
		return nil, err
	}
	if !ok || file.Kind != searchCacheKindRecord {
		return nil, ErrSidecarStoreAbsent
	}
	base := searchCachePartName(key, searchCachePartRecord)
	meta, err := self.readMeta(base)
	if err != nil {
		return nil, self.readFailed(key, err)
	}
	if len(meta.SealedHeader) != EvsRecordHeaderByteCount {
		return nil, self.readFailed(key, ErrSidecarStoreFailed)
	}
	return &SearchCacheRecordFrames{cache: self, key: key, base: base, meta: meta}, nil
}

// The sealed header as evs sealed it.
func (self *SearchCacheRecordFrames) SealedHeader() []byte {
	return bytes.Clone(self.meta.SealedHeader)
}

// The record body's length.
func (self *SearchCacheRecordFrames) Length() int64 {
	return self.meta.Length
}

// Frame index's plaintext, opened under header and objectKey, which the reader opened and holds, into dst, which holds a
// whole frame: one frame decrypted, nothing else of the record. A kept frame that does not open drops the file:
// ErrSearchCacheRefetch.
func (self *SearchCacheRecordFrames) ReadFrame(index int, header *EvsRecordHeader, objectKey *EvsObjectKey, fileId Id, dst []byte) ([]byte, error) {
	if index < 0 || self.meta.FrameCount <= index || header == nil || header.BodyLength != uint64(self.meta.Length) {
		return nil, fmt.Errorf("%w: a frame past the record", ErrSearchCacheArgs)
	}
	sealed, err := self.cache.readSmall(self.base+"/"+strconv.Itoa(index), searchCacheFrameMax)
	if err != nil {
		return nil, self.cache.readFailed(self.key, err)
	}
	frames := &evsRecordFrames{}
	if err := frames.begin(objectKey, self.key.RepoId, fileId, header); err != nil {
		return nil, err
	}
	frames.frameIndex = uint32(index)
	frames.frame()
	if len(dst) < len(sealed) {
		dst = make([]byte, len(sealed))
	}
	opened, err := frames.aead.Open(dst[:0], frames.nonce[:], sealed, frames.aad[:])
	if err != nil {
		return nil, self.cache.readFailed(self.key, ErrSidecarStoreFailed)
	}
	return opened, nil
}

// A frame source over a kept record for the index's readers (indexOpenShard, indexValidateFile): each frame opened as
// it is asked for.
func (self *SearchCacheRecordFrames) frameSource(header *EvsRecordHeader, objectKey *EvsObjectKey, fileId Id) indexFrameSource {
	return &searchRecordFrameSource{frames: self, header: header, objectKey: objectKey, fileId: fileId}
}

// indexFrameSource over a kept record.
type searchRecordFrameSource struct {
	frames    *SearchCacheRecordFrames
	header    *EvsRecordHeader
	objectKey *EvsObjectKey
	fileId    Id
}

// The record body's length.
func (self *searchRecordFrameSource) indexLength() int {
	return int(self.frames.meta.Length)
}

// Frame index's plaintext, opened under the reader's keys.
func (self *searchRecordFrameSource) indexReadFrame(index int, dst []byte) ([]byte, error) {
	return self.frames.ReadFrame(index, self.header, self.objectKey, self.fileId, dst)
}

// A read of a kept file failed: one that failed AEAD or decoding, or lost a part, is dropped with what derives from it
// and answered ErrSearchCacheRefetch (§5.9's rebuild row); a lock or a lost keychain is answered as it is, dropping
// nothing.
func (self *SearchCache) readFailed(key SearchCacheKey, err error) error {
	if !isSearchCacheDamage(err) {
		return err
	}
	self.log.Warningf("[search]a kept index file failed: dropped, to fetch again")
	if dropErr := self.Remove(key); dropErr != nil {
		return dropErr
	}
	return ErrSearchCacheRefetch
}

// Whether a read's error is damage to the kept file, which a refetch mends: AEAD or decoding, or a part gone while its
// meta says it is there. A lock, a lost keychain or a closed store is not.
func isSearchCacheDamage(err error) bool {
	return errors.Is(err, ErrSidecarStoreFailed) || errors.Is(err, ErrSidecarStoreAbsent)
}
