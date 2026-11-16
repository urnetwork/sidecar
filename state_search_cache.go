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
// under keys the cache never holds.
//
// Beside each record it keeps what reopens it after the round that fetched it (QD-838): the 72 B block wrapping its
// object key under fek_g exactly as its segment's header carried it, that generation g, and its file id. A reader
// holding RK_g from GkmClient, as any evs read gets it, opens it with no read of evs (OpenRecordRead): fek_g unwraps
// the object key and manifest_g opens the sealed header, both derived for the open and cleared after it, and the read
// holds the object key until it ends or the instance locks. A wrapped key is not a key, so the cache still holds none,
// and no key reaches a log or an error. A record kept before these reads as lacking them and stays, and the next sync
// round fetches it again (search_fetch.go).
//
// A slot-keyed repo's record (record-class repos and group inboxes, §11.14's keys row) has its key in a slot, not in
// its segment's header, and the cache keeps that too (QD-845): the slot's 72 B block exactly as the slot object carried
// it, under fek of the slot key's own generation, that generation, the segment's generation, whose manifest key seals
// the record's header, and the (slot_id, key_index) the record names. A reader asks gkm for RK at each generation,
// both when they differ, and reopens the record as a general repo's. An ERASE destroys slot keys at evs, and the cache
// drops at its hint (I-EVS-13 read as evs's storage plus a device cache that drops at the hint): DropErasedSlotKeys
// deletes at once every kept record whose (slot_id, key_index) the ERASE names and ends every read of one, so no
// wrapped block of a destroyed key, and no unwrapped key, stays past the hint's application. A slot-keyed record kept
// before the cache kept its block reads as lacking it and is fetched again. Derived data is state_search_derived.go's.
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

	"github.com/urnetwork/sidecar/protocol"
)

// §5.9's file class of the index cache and search state, the cache's directory and its names. Its bounds are
// SidecarSearchSettings'; a frame file holds one of evs's sealed frames.
const (
	SidecarSearchFileClass  = "search"
	sidecarSearchCacheDir   = "search"
	searchCacheHoldingsName = "holdings"
	searchCacheMetaName     = "m"
	searchCachePartRecord   = "record"
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
	// A kept record lacks what reopens it after its round: it was kept before the cache kept its wrapped object key,
	// generation and file id (QD-838), or, slot-keyed, before it kept its slot's block (QD-845). It stays, and the next
	// sync round fetches it again.
	ErrSearchCacheKeysLacking = errors.New("search cache: the kept record lacks the keys that reopen it; a sync round fetches it again")
	// A repo key a read was given does not open the kept record: another repo's or generation's, or one whose fek_g
	// does not unwrap the record's block or whose manifest_g does not open its header. Nothing is dropped.
	ErrSearchCacheKey = errors.New("search cache: the key given does not open the kept record")
	// A read of a kept record ended, by Close or a lock of the instance, and holds no key.
	ErrSearchCacheReadEnded = errors.New("search cache: the read ended")
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
	// manifest key, the object key it names, and the record's file id, its frames' AAD, which the cache keeps.
	Header    *EvsRecordHeader
	ObjectKey *EvsObjectKey
	FileId    Id
	// The 72 B block wrapping ObjectKey under fek_g, g the header's generation (QD-524), which the cache keeps with g and
	// the file id so a reader holding RK_g reopens the record after its round (QD-838). Required. For a record keyed by
	// its container (key_ref_kind 0), exactly as its segment header carried it; for a slot-keyed one (key_ref_kind 1),
	// the block of the key at (Header.SlotId, Header.KeyIndex) exactly as its slot object carried it (QD-845), which
	// the fetch takes while it holds the slot object (SetSlotKey).
	WrappedObjectKey []byte
	// A slot-keyed record's two generations (QD-845), both required on one and refused on any other: the slot key's
	// own, whose fek wraps WrappedObjectKey and which the header names, and its segment's, whose manifest key seals
	// SealedHeader. They differ where the slot key is older than the segment.
	SlotKeyGeneration uint64
	SegmentGeneration uint64
}

// Takes a slot-keyed record's key from slot, the slot object its header names by Header.SlotId, as the fetch holds
// it, and segmentGeneration, the generation of the segment that carried the record (QD-845): the 72 B block at
// Header.KeyIndex exactly as the slot carries it, and that key's generation, which is the header's. ErrSearchCacheArgs
// for a record that is not slot-keyed, a slot without the key (an ERASE dropped it), a key of another generation than
// the header's, and a key that is not a 72 B block under fek (a record slot row, a deposit's).
func (self *SearchCacheRecord) SetSlotKey(slot *protocol.EvsSlotObject, segmentGeneration uint64) error {
	header := self.Header
	if header == nil || header.KeyRefKind != protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT || segmentGeneration == 0 {
		return fmt.Errorf("%w: a slot key for a record that names none", ErrSearchCacheArgs)
	}
	slotKey, ok := EvsSlotKeyAt(slot, uint32(header.KeyIndex))
	if !ok || slotKey.GetGeneration() != header.Generation || len(slotKey.GetWrapped()) != EvsWrappedKeyByteCount {
		return fmt.Errorf("%w: a slot without the record's key", ErrSearchCacheArgs)
	}
	self.WrappedObjectKey = bytes.Clone(slotKey.GetWrapped())
	self.SlotKeyGeneration = slotKey.GetGeneration()
	self.SegmentGeneration = segmentGeneration
	return nil
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
	// For a record: kept with what reopens it after its round, its wrapped object key, generations and file id (QD-838,
	// QD-845). False for a record kept before, which the next sync round fetches again.
	KeysKept bool
	// For a slot-keyed record kept with its keys: the slot key it names, which an ERASE's hint drops it by
	// (DropErasedSlotKeys).
	SlotKeyed bool
	SlotId    Id
	KeyIndex  uint16
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
	Keys     bool   `json:"keys,omitempty"`
	// a slot-keyed record's slot id, lowercase hex, and key index
	SlotId   string `json:"slot_id,omitempty"`
	KeyIndex uint16 `json:"key_index,omitempty"`
}

// A kept file's meta: its frames and, for a record, its sealed header, its file id and what reopens it (QD-838): the
// wrapped object key with the generation whose fek wraps it, which is the one its header names. A slot-keyed record's
// is marked so and keeps besides (QD-845) the generation of its segment, whose manifest key seals the header, and the
// slot key it names. A record's meta written before QD-838 has no block, file id or generation, and a slot-keyed
// one's written before QD-845 the mark alone.
type searchCacheMetaWire struct {
	Length       int64  `json:"length"`
	FrameCount   int    `json:"frames"`
	SealedHeader []byte `json:"header,omitempty"`
	Sha256       string `json:"sha256,omitempty"`
	WrappedKey   []byte `json:"wrapped_key,omitempty"`
	FileId       string `json:"file_id,omitempty"`
	Generation   uint64 `json:"generation,omitempty"`
	SlotKeyed    bool   `json:"slot_keyed,omitempty"`
	// slot-keyed records only
	SegmentGeneration uint64 `json:"segment_generation,omitempty"`
	SlotId            string `json:"slot_id,omitempty"`
	KeyIndex          uint16 `json:"key_index,omitempty"`
}

// Whether a reader may reopen the meta's record under its repo keys (QD-838, QD-845): nil where it keeps the record's
// wrapped object key, generation and file id and, slot-keyed, its segment's generation and slot id;
// ErrSearchCacheKeysLacking for one kept before the cache kept them; ErrSidecarStoreFailed for a block of the wrong
// length, and for a slot's fields on a record not marked slot-keyed.
func (self *searchCacheMetaWire) keysState() error {
	switch {
	case self.Generation == 0 || self.FileId == "":
		return ErrSearchCacheKeysLacking
	case self.SlotKeyed && (self.SegmentGeneration == 0 || self.SlotId == ""):
		return ErrSearchCacheKeysLacking
	case !self.SlotKeyed && (self.SegmentGeneration != 0 || self.SlotId != "" || self.KeyIndex != 0):
		return fmt.Errorf("%w: a slot on a kept container-keyed record", ErrSidecarStoreFailed)
	case len(self.WrappedKey) != EvsWrappedKeyByteCount:
		return fmt.Errorf("%w: a kept record's wrapped key", ErrSidecarStoreFailed)
	}
	return nil
}

// The generation whose manifest key seals the kept record's header: its segment's, which for a container-keyed record
// is the one generation it keeps (QD-524).
func (self *searchCacheMetaWire) headerGeneration() uint64 {
	if self.SlotKeyed {
		return self.SegmentGeneration
	}
	return self.Generation
}

// The index cache. Construct with NewSearchCache.
type SearchCache struct {
	store    SidecarStore
	settings *SidecarSearchSettings
	clock    Clock
	log      Logger
	// whether the cache lives in memory (Search.CacheByteCount 0)
	memory bool
	// the instance whose store this is, whose locks end reads and cursors; nil for a store of none
	instance *SidecarInstance
	cancel   context.CancelFunc
	done     chan struct{}
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
	// open reads of kept records, which an ERASE's hint ends for the records it drops (DropErasedSlotKeys); each is
	// among the cursors too
	reads map[*SearchCacheRecordRead]bool
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
		settings.MemoryByteCount < settings.VersionCacheByteCount || settings.CacheHoldingsByteCount <= 0 ||
		settings.CacheMetaByteCount <= 0 {
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
		reads:        map[*SearchCacheRecordRead]bool{},
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
	self.instance = instance
	go self.watchLock(watchCtx, instance)
	return self, nil
}

// Why the instance this cache's store belongs to opens nothing now: nil while it is open, and for a store of no
// instance.
func (self *SearchCache) instanceError() error {
	if self.instance == nil {
		return nil
	}
	return self.instance.stateError()
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
// stay, sealed; a cache kept in memory, whose derived parts are plaintext there, drops them all, since everything in it
// is refetched or derived again.
func (self *SearchCache) Locked() {
	self.decoded.drop()
	self.versionPages.drop()
	if memoryStore, ok := self.store.(*searchMemoryStore); ok {
		memoryStore.clear()
		self.stateLock.Lock()
		clear(self.refs)
		self.byteCount = 0
		self.stateLock.Unlock()
	}
	cursors := func() []func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		cursors := make([]func(), 0, len(self.cursors))
		for _, end := range self.cursors {
			cursors = append(cursors, end)
		}
		clear(self.cursors)
		clear(self.reads)
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
	content, err := self.readSmall(searchCacheRefName(repoId, refId)+"/"+searchCacheHoldingsName, self.settings.CacheHoldingsByteCount)
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
				KeysKept:  file.Keys,
			}
			if file.SlotId != "" {
				slotId, err := searchCacheIdOfHex(file.SlotId)
				if err != nil {
					continue
				}
				kept.SlotKeyed, kept.SlotId, kept.KeyIndex = true, slotId, file.KeyIndex
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
		fileWire := searchCacheFileWire{
			Path:     file.Key.Path,
			Version:  file.Key.Version,
			Sha256:   hex.EncodeToString(file.ContentSha256[:]),
			All:      file.Partition.All,
			StartDay: file.Partition.StartDay,
			Kind:     file.Kind,
			Bytes:    file.ByteCount,
			KeptMs:   file.KeptAt.UnixMilli(),
			Keys:     file.KeysKept,
		}
		if file.SlotKeyed {
			fileWire.SlotId, fileWire.KeyIndex = hex.EncodeToString(file.SlotId[:]), file.KeyIndex
		}
		wire.Files = append(wire.Files, fileWire)
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
	content, err := self.readSmall(base+"/"+searchCacheMetaName, self.settings.CacheMetaByteCount)
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
// before a record is kept. Before it, the record must carry what reopens it later as its key ref kind says (QD-838,
// QD-845): its 72 B wrapped block and a file id, and, slot-keyed, its slot key's generation, which is its header's,
// and its segment's, neither of which a container-keyed record carries apart from its header's. Answers the sealed
// frames, split.
func searchCacheCheckRecord(record *SearchCacheRecord) ([][]byte, error) {
	header := record.Header
	if header == nil || record.ObjectKey == nil || len(record.SealedHeader) != EvsRecordHeaderByteCount {
		return nil, fmt.Errorf("%w: a record without its header or key", ErrSearchCacheArgs)
	}
	if len(record.WrappedObjectKey) != EvsWrappedKeyByteCount || record.FileId == (Id{}) {
		return nil, fmt.Errorf("%w: a record without its wrapped object key or file id", ErrSearchCacheArgs)
	}
	switch header.KeyRefKind {
	case protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER:
		// evs's readers hold a container-keyed record's generation to its segment's, whose g seals the header and wraps
		// the block alike
		if record.SlotKeyGeneration != 0 || (record.SegmentGeneration != 0 && record.SegmentGeneration != header.Generation) {
			return nil, fmt.Errorf("%w: a slot key's generations on a container-keyed record", ErrSearchCacheArgs)
		}
	case protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT:
		// evs's readers hold a slot-keyed record's generation to its slot key's own
		if header.SlotId == (Id{}) || record.SlotKeyGeneration != header.Generation || record.SegmentGeneration == 0 {
			return nil, fmt.Errorf("%w: a slot-keyed record without its slot key's and segment's generations", ErrSearchCacheArgs)
		}
	default:
		return nil, fmt.Errorf("%w: a record of key ref kind %d", ErrSearchCacheArgs, header.KeyRefKind)
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
// The record's frames are kept as evs sealed them, and beside them its file id, its wrapped object key and the
// header's generation, whose fek wraps it: for a container-keyed record that generation's keys seal the header too
// (QD-524, QD-838); a slot-keyed record is marked so, with its segment's generation, whose manifest key seals the
// header, and the slot key it names, which an ERASE's hint drops it by (QD-845). A record without what its key ref
// kind needs is ErrSearchCacheArgs. A copy kept before at the same key is replaced. The cache's bound then applies
// (Evict).
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
	meta := &searchCacheMetaWire{
		Length:       int64(record.Header.BodyLength),
		FrameCount:   len(frames),
		SealedHeader: bytes.Clone(record.SealedHeader),
		Sha256:       hex.EncodeToString(record.ContentSha256[:]),
		FileId:       hex.EncodeToString(record.FileId[:]),
		WrappedKey:   bytes.Clone(record.WrappedObjectKey),
		Generation:   record.Header.Generation,
	}
	file := SearchCacheFile{
		Key:           record.Key,
		ContentSha256: record.ContentSha256,
		Partition:     record.Partition,
		Kind:          searchCacheKindRecord,
		KeysKept:      true,
	}
	if record.Header.KeyRefKind == protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT {
		meta.SlotKeyed = true
		meta.SegmentGeneration = record.SegmentGeneration
		meta.SlotId = hex.EncodeToString(record.Header.SlotId[:])
		meta.KeyIndex = record.Header.KeyIndex
		file.SlotKeyed, file.SlotId, file.KeyIndex = true, record.Header.SlotId, record.Header.KeyIndex
	}
	if err := func() error {
		self.operationLock.Lock()
		defer self.operationLock.Unlock()
		ref, err := self.loadRefWithLock(record.Key.RepoId, record.Key.RefId)
		if err != nil {
			return err
		}
		byteCount, err := self.writeFramed(searchCachePartName(record.Key, searchCachePartRecord), frames, meta)
		if err != nil {
			return err
		}
		file.ByteCount, file.KeptAt = byteCount, self.clock.Now()
		self.keepFileWithLock(ref, file)
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

// Drops everything the cache holds of every repo: `ur search sync --evict` and DropSearchCache with no repo. search.state
// is not in the cache's directory, so it stays (§5.9's state row).
func (self *SearchCache) DropAll() error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	entries, err := self.store.List("")
	if err != nil {
		return err
	}
	// metas first, so no reader takes a part for whole
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
		if err := self.removeSized(entry.Name, entry.ByteCount); err != nil {
			return err
		}
		yield.step()
	}
	self.decoded.drop()
	self.versionPages.drop()
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	clear(self.refs)
	return nil
}

// A kept record's frames, read one at a time (§5.9's bounds row): the sealed header as fetched, which the reader opens
// under its manifest key, and each frame, opened under the object key it names, so one 64 KiB frame is decrypted at a
// time and nothing of the record is decrypted at rest. With the repo key at its Generation, and for a slot-keyed
// record at its HeaderGeneration too, OpenRead and OpenReadKeys open it for a read that needs no other key (QD-838,
// QD-845).
type SearchCacheRecordFrames struct {
	cache *SearchCache
	key   SearchCacheKey
	base  string
	meta  *searchCacheMetaWire
}

// The kept record at key, with what reopens it: its file id, its wrapped object key and its generations (QD-838,
// QD-845). ErrSidecarStoreAbsent for a record the cache does not hold; ErrSearchCacheRefetch for one that failed and
// was dropped.
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

// The 72 B block wrapping the record's object key under fek_g as its segment header carried it (QD-838) or, for a
// slot-keyed record, as its slot object did (QD-845); nil for a record kept before the cache kept it.
func (self *SearchCacheRecordFrames) WrappedObjectKey() []byte {
	return bytes.Clone(self.meta.WrappedKey)
}

// g, whose RK_g a reader asks of GkmClient to reopen the record: its fek wraps the object key, and for a
// container-keyed record its manifest key seals the header too (QD-524). A slot-keyed record's is its slot key's own
// generation. 0 for a record kept before the cache kept it.
func (self *SearchCacheRecordFrames) Generation() uint64 {
	return self.meta.Generation
}

// The generation whose manifest key seals the record's header, its segment's: Generation for a container-keyed
// record, and for a slot-keyed one what its fetch gave, which is newer where the slot key is older than the segment
// (QD-845). 0 for a record kept before the cache kept it.
func (self *SearchCacheRecordFrames) HeaderGeneration() uint64 {
	return self.meta.headerGeneration()
}

// The slot key a slot-keyed record names, which an ERASE destroys: false for a container-keyed record and one kept
// before the cache kept its slot's block (QD-845).
func (self *SearchCacheRecordFrames) SlotKey() (*EvsErasedKey, bool) {
	if !self.meta.SlotKeyed || self.meta.keysState() != nil {
		return nil, false
	}
	slotId, err := searchCacheIdOfHex(self.meta.SlotId)
	if err != nil {
		return nil, false
	}
	return &EvsErasedKey{SlotId: slotId, KeyIndex: self.meta.KeyIndex}, true
}

// The record's file id, its frames' AAD: ErrSearchCacheKeysLacking for a record kept before the cache kept it
// (QD-838), and ErrSearchCacheRefetch, the file dropped, where the meta holds a malformed one.
func (self *SearchCacheRecordFrames) FileId() (Id, error) {
	if self.meta.FileId == "" {
		return Id{}, ErrSearchCacheKeysLacking
	}
	decoded, err := hex.DecodeString(self.meta.FileId)
	if err != nil || len(decoded) != len(Id{}) {
		return Id{}, self.cache.readFailed(self.key, ErrSidecarStoreFailed)
	}
	return Id(decoded), nil
}

// The record body's length.
func (self *SearchCacheRecordFrames) Length() int64 {
	return self.meta.Length
}

// Frame index's plaintext, opened under header and objectKey, which the reader opened and holds, into dst, which holds a
// whole frame: one frame decrypted, nothing else of the record. A kept frame that does not open drops the file:
// ErrSearchCacheRefetch.
func (self *SearchCacheRecordFrames) ReadFrame(index int, header *EvsRecordHeader, objectKey *EvsObjectKey, fileId Id, dst []byte) ([]byte, error) {
	sealed, err := self.readSealedFrame(index, header)
	if err != nil {
		return nil, err
	}
	opened, ok, err := self.openFrame(index, sealed, header, objectKey, fileId, dst)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, self.cache.readFailed(self.key, ErrSidecarStoreFailed)
	}
	return opened, nil
}

// Frame index's sealed bytes as kept, for a record of header's length; a part gone drops the file:
// ErrSearchCacheRefetch.
func (self *SearchCacheRecordFrames) readSealedFrame(index int, header *EvsRecordHeader) ([]byte, error) {
	if index < 0 || self.meta.FrameCount <= index || header == nil || header.BodyLength != uint64(self.meta.Length) {
		return nil, fmt.Errorf("%w: a frame past the record", ErrSearchCacheArgs)
	}
	sealed, err := self.cache.readSmall(self.base+"/"+strconv.Itoa(index), searchCacheFrameMax)
	if err != nil {
		return nil, self.cache.readFailed(self.key, err)
	}
	return sealed, nil
}

// Frame index's plaintext from its sealed bytes under the keys given, into dst: false where its tag fails. Only memory
// is touched, so a read holding its key under a lock may call it.
func (self *SearchCacheRecordFrames) openFrame(index int, sealed []byte, header *EvsRecordHeader, objectKey *EvsObjectKey, fileId Id, dst []byte) ([]byte, bool, error) {
	frames := &evsRecordFrames{}
	if err := frames.begin(objectKey, self.key.RepoId, fileId, header); err != nil {
		return nil, false, err
	}
	frames.frameIndex = uint32(index)
	frames.frame()
	// the reader's own frame buffer takes the plaintext, so a cursor holds one frame and no more
	if len(sealed) < chacha20poly1305.Overhead || cap(dst) < len(sealed)-chacha20poly1305.Overhead {
		dst = make([]byte, 0, max(len(sealed), chacha20poly1305.Overhead))
	}
	opened, err := frames.aead.Open(dst[:0], frames.nonce[:], sealed, frames.aad[:])
	if err != nil {
		return nil, false, nil
	}
	return opened, true, nil
}

// keysState, a block of the wrong length dropping the file: ErrSearchCacheRefetch. A record that lacks its keys while
// its holdings entry says it keeps them, a slot-keyed one kept before the cache kept its slot's block (QD-845), has
// the entry unmarked, so the next sync round fetches it again.
func (self *SearchCacheRecordFrames) checkKeys() error {
	err := self.meta.keysState()
	switch {
	case err == nil:
		return nil
	case isSearchCacheDamage(err):
		return self.cache.readFailed(self.key, err)
	case errors.Is(err, ErrSearchCacheKeysLacking):
		if unmarkErr := self.cache.unmarkKeys(self.key); unmarkErr != nil {
			return unmarkErr
		}
	}
	return err
}

// Marks the kept record at key as lacking the keys that reopen it, where its holdings entry says it keeps them.
func (self *SearchCache) unmarkKeys(key SearchCacheKey) error {
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	ref, err := self.loadRefWithLock(key.RepoId, key.RefId)
	if err != nil {
		return err
	}
	unmarked := func() bool {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for index := range ref.Files {
			file := &ref.Files[index]
			if file.Key == key && file.Kind == searchCacheKindRecord && file.KeysKept {
				file.KeysKept, file.SlotKeyed, file.SlotId, file.KeyIndex = false, false, Id{}, 0
				return true
			}
		}
		return false
	}()
	if !unmarked {
		return nil
	}
	return self.storeRefWithLock(ref)
}

// Opens the kept record for one read under repoKey, RK_g of the record's repo at its Generation, where that
// generation's keys seal its header too: every container-keyed record, and a slot-keyed one whose slot key and
// segment share a generation. Answers as OpenReadKeys does, and ErrSearchCacheKey for a slot-keyed record whose
// generations differ.
func (self *SearchCacheRecordFrames) OpenRead(repoKey *EvsRepoKey) (*SearchCacheRecordRead, error) {
	return self.OpenReadKeys(repoKey, repoKey)
}

// Opens the kept record for one read under the record's repo's keys, which the reader asks of GkmClient as any evs
// read does (OpenRecordRead asks it), so a record kept in an earlier round reads with no read of evs (QD-838):
// keyRepoKey is RK at its Generation, whose fek unwraps the object key from the block the record's segment header or
// slot object carried, with AAD "UR evs 1.0 object key"; headerRepoKey is RK at its HeaderGeneration, whose manifest
// key opens its sealed header. They are one key for a container-keyed record and may be two for a slot-keyed one
// (QD-845). Each derived key is cleared once used; the read holds the object key until it ends.
// ErrSearchCacheKeysLacking for a record kept before the cache kept its keys, which stays for the next sync round to
// fetch again; ErrSearchCacheKey, dropping nothing, for a key of another repo or generation or one that does not
// unwrap the block or open the header. A header that opens but is not the record its keys were kept for, a
// slot-keyed one naming another slot key among them, drops the file: ErrSearchCacheRefetch. ErrSidecarStoreAbsent for
// a record the cache dropped since OpenRecord, as an ERASE's hint drops one. An instance that is not open answers its
// state's error, such as ErrSidecarStoreLocked, and a lock or a drop while the key is unwrapped
// ErrSearchCacheReadEnded, the key cleared either way.
func (self *SearchCacheRecordFrames) OpenReadKeys(keyRepoKey *EvsRepoKey, headerRepoKey *EvsRepoKey) (*SearchCacheRecordRead, error) {
	if err := self.checkKeys(); err != nil {
		return nil, err
	}
	fileId, err := self.FileId()
	if err != nil {
		return nil, err
	}
	for _, held := range []struct {
		repoKey    *EvsRepoKey
		generation uint64
	}{{keyRepoKey, self.meta.Generation}, {headerRepoKey, self.meta.headerGeneration()}} {
		if held.repoKey == nil || held.repoKey.RepoId() != self.key.RepoId || held.repoKey.Generation() != held.generation {
			return nil, fmt.Errorf("%w: a key of another repo or generation", ErrSearchCacheKey)
		}
	}
	// a lock of the instance ends the read as it ends a cursor (§5.9's delete row), and so does an ERASE's hint that
	// drops the record: registered before any key exists, so a lock or a drop after this ends it, and one before it is
	// the instance's state or the record's absence, checked next
	read := &SearchCacheRecordRead{frames: self, fileId: fileId}
	read.release = self.cache.addRead(read)
	if err := self.cache.instanceError(); err != nil {
		read.Close()
		return nil, err
	}
	if file, ok, err := self.cache.heldFile(self.key); err != nil || !ok || file.Kind != searchCacheKindRecord {
		read.Close()
		if err != nil {
			return nil, err
		}
		return nil, ErrSidecarStoreAbsent
	}
	objectKey, err := func() (*EvsObjectKey, error) {
		fekKey, err := NewEvsFekKey(keyRepoKey)
		if err != nil {
			return nil, err
		}
		defer clear(fekKey.key)
		return EvsUnwrapObjectKey(fekKey, self.meta.WrappedKey)
	}()
	if err != nil {
		read.Close()
		return nil, fmt.Errorf("%w: %w", ErrSearchCacheKey, err)
	}
	header, err := func() (*EvsRecordHeader, error) {
		manifestKey, err := NewEvsManifestKey(headerRepoKey)
		if err != nil {
			return nil, err
		}
		defer clear(manifestKey.key)
		return EvsOpenRecordHeader(manifestKey, self.meta.SealedHeader)
	}()
	if err != nil {
		clear(objectKey.key)
		read.Close()
		return nil, fmt.Errorf("%w: %w", ErrSearchCacheKey, err)
	}
	if !self.meta.keptFor(header) {
		clear(objectKey.key)
		read.Close()
		return nil, self.cache.readFailed(self.key, ErrSidecarStoreFailed)
	}
	held := func() bool {
		read.stateLock.Lock()
		defer read.stateLock.Unlock()
		if read.ended {
			return false
		}
		read.header = header
		read.objectKey = objectKey
		return true
	}()
	if !held {
		// a lock or a drop came while the key was unwrapped
		clear(objectKey.key)
		read.Close()
		return nil, ErrSearchCacheReadEnded
	}
	return read, nil
}

// Whether header, opened from the meta's sealed header, is the record the meta's keys were kept for: its length and
// frames, the generation its block is wrapped under, and its key ref, which for a slot-keyed record is the slot key
// the meta names.
func (self *searchCacheMetaWire) keptFor(header *EvsRecordHeader) bool {
	if header.Generation != self.Generation || header.BodyLength != uint64(self.Length) ||
		EvsRecordFrameCount(header.BodyLength) != uint64(self.FrameCount) {
		return false
	}
	if !self.SlotKeyed {
		return header.KeyRefKind == protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER
	}
	slotId, err := searchCacheIdOfHex(self.SlotId)
	return err == nil && header.KeyRefKind == protocol.EvsKeyRefKind_EVS_KEY_REF_SLOT && header.SlotId == slotId &&
		header.KeyIndex == self.KeyIndex
}

// Registers an open read of a kept record among the cache's cursors, which a lock ends, and its reads, which an
// ERASE's hint ends for the records it drops. The answer removes it from both.
func (self *SearchCache) addRead(read *SearchCacheRecordRead) func() {
	releaseCursor := self.AddCursor(read.end)
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.reads[read] = true
	return func() {
		releaseCursor()
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		delete(self.reads, read)
	}
}

// The kept record at key opened for one read (QD-838), with RK at the record's generations asked of gkm as any evs
// read asks it, once where one generation's keys wrap its object key and seal its header and at each where a
// slot-keyed record's slot key is of another generation than its segment (QD-845): what a search, local or remote,
// reads a kept shard, posting list or slot through after the round that fetched it, with no read of evs. Answers as
// OpenRecord and OpenReadKeys do, and gkm's own refusals as they are, such as ErrGkmKeyMissing for a generation this
// sidecar no longer reaches.
func (self *SearchCache) OpenRecordRead(ctx context.Context, key SearchCacheKey, gkm GkmClient) (*SearchCacheRecordRead, error) {
	if gkm == nil {
		return nil, fmt.Errorf("%w: a read needs gkm", ErrSearchCacheArgs)
	}
	frames, err := self.OpenRecord(key)
	if err != nil {
		return nil, err
	}
	if err := frames.checkKeys(); err != nil {
		return nil, err
	}
	keyRepoKey, err := gkm.RepoKey(ctx, key.RepoId, frames.meta.Generation)
	if err != nil {
		return nil, err
	}
	headerRepoKey := keyRepoKey
	if headerGeneration := frames.meta.headerGeneration(); headerGeneration != frames.meta.Generation {
		if headerRepoKey, err = gkm.RepoKey(ctx, key.RepoId, headerGeneration); err != nil {
			return nil, err
		}
	}
	return frames.OpenReadKeys(keyRepoKey, headerRepoKey)
}

// What an ERASE's hint does to the cache's kept records of a slot-keyed repo (QD-845; CORE-M10-04's hint handling
// calls it for every ERASE it applies, beside the versions a CLOSURE replaced): at once, every kept record of the repo,
// on every ref, whose (slot_id, key_index) is one of erased, the slot keys the ERASE destroys, is deleted with its
// derived data, the 72 B block wrapping the destroyed key with it, and every open read of one ends, its unwrapped key
// cleared. So once this returns no kept file and no read holds a key to an erased document (I-EVS-13 read as evs's
// storage plus a device cache that drops at the hint). Answers the files it dropped, for the caller's masks. A
// slot-keyed record kept before the cache kept its slot's block names no slot here and holds no block: it stays, and
// opens for no one until it is fetched again.
func (self *SearchCache) DropErasedSlotKeys(repoId Id, erased []*EvsErasedKey) ([]SearchCacheKey, error) {
	if repoId == (Id{}) {
		return nil, fmt.Errorf("%w: an erasure of no repo", ErrSearchCacheArgs)
	}
	named := map[EvsErasedKey]bool{}
	for _, key := range erased {
		if key == nil || key.SlotId == (Id{}) {
			return nil, fmt.Errorf("%w: an erased key of no slot", ErrSearchCacheArgs)
		}
		named[*key] = true
	}
	if len(named) == 0 {
		return nil, nil
	}
	self.operationLock.Lock()
	defer self.operationLock.Unlock()
	refKeys, err := self.refKeysWithLock()
	if err != nil {
		return nil, err
	}
	dropped := []SearchCacheKey{}
	// the reads end whatever a removal answers, so a failed removal leaves no unwrapped key either
	defer func() {
		self.endReads(dropped)
	}()
	for _, refKey := range refKeys {
		if refKey[0] != repoId {
			continue
		}
		ref, err := self.loadRefWithLock(refKey[0], refKey[1])
		if err != nil {
			return dropped, err
		}
		keys := func() []SearchCacheKey {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			keys := []SearchCacheKey{}
			for _, file := range ref.Files {
				if file.Kind == searchCacheKindRecord && file.SlotKeyed && named[EvsErasedKey{SlotId: file.SlotId, KeyIndex: file.KeyIndex}] {
					keys = append(keys, file.Key)
				}
			}
			return keys
		}()
		for _, key := range keys {
			dropped = append(dropped, key)
			if err := self.removeFileWithLock(key); err != nil {
				return dropped, err
			}
		}
	}
	return dropped, nil
}

// Ends every open read of the kept records at keys, clearing the object key each holds.
func (self *SearchCache) endReads(keys []SearchCacheKey) {
	if len(keys) == 0 {
		return
	}
	reads := func() []*SearchCacheRecordRead {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		reads := []*SearchCacheRecordRead{}
		for read := range self.reads {
			if slices.Contains(keys, read.frames.key) {
				reads = append(reads, read)
			}
		}
		return reads
	}()
	for _, read := range reads {
		read.end()
	}
}

// A kept record opened for one read (QD-838): its header opened and its object key unwrapped, which it holds until
// Close, a lock of the instance, or an ERASE's hint that drops the record (DropErasedSlotKeys) clears and drops it; a
// frame read after any is ErrSearchCacheReadEnded. Each
// ReadFrame decrypts one 64 KiB frame and nothing else of the record. It serves the index's readers as their frame
// source. Close and a lock are safe beside a read; reads are not safe for concurrent use with each other.
type SearchCacheRecordRead struct {
	frames *SearchCacheRecordFrames
	fileId Id
	// takes the read out of the cache's open cursors
	release func()

	stateLock sync.Mutex
	// the opened header and the record's object key, set once OpenRead has both, the key nil again once the read ends
	header    *EvsRecordHeader
	objectKey *EvsObjectKey
	ended     bool
}

// The record body's length.
func (self *SearchCacheRecordRead) Length() int64 {
	return self.frames.meta.Length
}

// The frames the body takes.
func (self *SearchCacheRecordRead) FrameCount() int {
	return self.frames.meta.FrameCount
}

// Frame index's plaintext into dst, which holds a whole frame: one frame decrypted, nothing else of the record. A kept
// frame that does not open, or a part gone, drops the file: ErrSearchCacheRefetch. ErrSearchCacheReadEnded once the
// read ended.
func (self *SearchCacheRecordRead) ReadFrame(index int, dst []byte) ([]byte, error) {
	header, open := func() (*EvsRecordHeader, bool) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		return self.header, !self.ended
	}()
	if !open {
		return nil, ErrSearchCacheReadEnded
	}
	sealed, err := self.frames.readSealedFrame(index, header)
	if err != nil {
		return nil, err
	}
	// the key is used under the lock, which only memory work holds, so an end never clears it mid-frame
	opened, ok, err := func() ([]byte, bool, error) {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.ended {
			return nil, false, ErrSearchCacheReadEnded
		}
		return self.frames.openFrame(index, sealed, header, self.objectKey, self.fileId, dst)
	}()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, self.frames.cache.readFailed(self.frames.key, ErrSidecarStoreFailed)
	}
	return opened, nil
}

// Ends the read: the object key is cleared and dropped. Safe to call more than once.
func (self *SearchCacheRecordRead) Close() {
	self.end()
	self.release()
}

// Ends the read, clearing and dropping the object key if it holds one: Close's, a lock's through the cache's open
// cursors, and a drop's through its open reads, either of which may come before OpenReadKeys has the key.
func (self *SearchCacheRecordRead) end() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.ended = true
	if self.objectKey != nil {
		clear(self.objectKey.key)
		self.objectKey = nil
	}
}

// The record body's length, as the index's readers ask it.
func (self *SearchCacheRecordRead) indexLength() int {
	return int(self.frames.meta.Length)
}

// Frame index's plaintext, as the index's readers ask it.
func (self *SearchCacheRecordRead) indexReadFrame(index int, dst []byte) ([]byte, error) {
	return self.ReadFrame(index, dst)
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
