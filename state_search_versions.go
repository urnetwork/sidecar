//go:build !ios_extension

// §5.9's version table (CORE-M10-02; D-CORE-16, D-EVS-52, FI-18, FS-109): per index root, for each doc key and ref id the
// partitions this device keeps hold, the record of its highest version there, whether that is a tombstone, and the file
// holding it, which §11.14's newest row probes one candidate at a time, in rank order, so a search never builds a set of
// a partition's keys in memory (FS-109 fails per-search key collection).
//
// The table is immutable runs. Each fills one slot of the root: a bucket's shards (their doc and tombstone tables), a
// bucket's other files (sealed slots, heads, large entries), all's shards, or erased keys: the keys an ERASE names,
// masked at every version until the rewritten files are cached, and the documents a ref's erasure set lists, masked at
// or below their version (§11.14's epoch row). A run is built by a streaming merge of key-ordered inputs
// (state_search_versions_merge.go) and never changes; the sync engine's manifest names the runs a snapshot reads, and a
// run no manifest names goes once no open snapshot holds it, so a running search keeps its snapshot's runs as it keeps
// its files.
//
// A run is a static tree of fixed-size pages, Search.VersionPageByteCount (4 KiB), each its own sealed file of the
// index cache under the local search key, its name in the AAD (state_search_cache.go's layout, part versions):
//
//	<repo>/<ref>/p<hex root>/<run id>/versions/m     the run's meta, written last: its commit point
//	<repo>/<ref>/p<hex root>/<run id>/versions/<i>   page i
//
//	page        kind (1 B: 0 data, 1 index) | count (u16 big-endian) | entries | zeros to the page's size
//	data entry  class (1 B: 0 a doc_key, 1 a ref tombstone's ref_id) | key (16 B) | VByte version |
//	            flags (1 B: bit 0 tombstone) | VByte file ordinal
//	index entry class | key | VByte child page
//
// Entries ascend by (class, key), one record a key; an index page's entries are its children's first keys. Pages are
// numbered in the order they were written, the root last. The meta holds the slot, the levels, the root, the counts
// and the file table that ordinals index. A probe reads one page a level of each run, through the cache's version-page
// LRU, Search.VersionCacheByteCount a process (256 KiB, 64 pages), decrypting one 4 KiB page at a time, so a search's
// mask state is its pending candidates whatever the partitions hold.
//
// Never stored: a query, hit or anything a search asked; a run holds only what the files it was built from hold. A run
// that fails AEAD or decoding is dropped and answered ErrSearchCacheRefetch, since the table is derived and the sync
// engine builds it again; a probe that fails so masks the candidate (fail closed).
//
// On every leg but the forwarding one: root Id, no connect type. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	// A page's kinds.
	searchVersionPageData  = 0
	searchVersionPageIndex = 1
	// An entry's classes: a document's doc_key, or a ref tombstone's ref_id.
	searchVersionClassDocument = 0
	searchVersionClassRef      = 1
	// A data entry's flags.
	searchVersionFlagTombstone = 1
	// A page's header: its kind and its entry count.
	searchVersionPageHeaderByteCount = 3
	// The meta's encoding version.
	searchVersionMetaVersion = 1
	// The longest data entry: class, key, two VBytes and the flags.
	searchVersionEntryMaxByteCount = 1 + indexIdByteCount + 2*indexVByteMaxByteCount + 1
)

var (
	// What a table call asks is not well formed.
	ErrSearchVersionArgs = errors.New("search version table: invalid arguments")
)

// The version an erased record masks every version at: an ERASE's keys, until the rewritten files are cached.
const SearchVersionErasedAll = math.MaxUint64

// What a run fills of a root's table (§5.9's versions row).
type SearchVersionSlotKind int

const (
	// A bucket's shards: their doc and tombstone tables.
	SearchVersionShards SearchVersionSlotKind = 1
	// A bucket's other files: sealed slots, heads and large entries.
	SearchVersionOthers SearchVersionSlotKind = 2
	// All's shards.
	SearchVersionAll SearchVersionSlotKind = 3
	// Erased keys: an ERASE's (at SearchVersionErasedAll) or an erasure set's documents (at their listed version).
	SearchVersionErased SearchVersionSlotKind = 4
)

// One slot of a root's table: its kind, and a bucket's start day for shards and others.
type SearchVersionSlot struct {
	Kind     SearchVersionSlotKind
	StartDay uint32
}

// A slot the table takes: a bucket's slots name a day, the others none.
func (self SearchVersionSlot) check() error {
	switch self.Kind {
	case SearchVersionShards, SearchVersionOthers:
		return nil
	case SearchVersionAll, SearchVersionErased:
		if self.StartDay == 0 {
			return nil
		}
	}
	return fmt.Errorf("%w: slot %+v", ErrSearchVersionArgs, self)
}

// The file holding a record: its path under the index root and its entry version.
type SearchVersionFile struct {
	Path    string
	Version uint64
}

// One record: a key's highest version among a run's inputs.
type SearchVersionRecord struct {
	// A document's doc_key, or with RefTombstone a ref tombstone's ref_id.
	Key          [indexIdByteCount]byte
	RefTombstone bool
	// The version; in an erased run, the version masked at and below.
	Version uint64
	// A document's tombstone. A ref tombstone's record is one by its class.
	Tombstone bool
	// The file it came from. Erased records name the erasure's source, or none.
	File SearchVersionFile
}

// The order records take: class, then key.
func compareSearchVersionRecords(a *SearchVersionRecord, b *SearchVersionRecord) int {
	if a.RefTombstone != b.RefTombstone {
		if a.RefTombstone {
			return 1
		}
		return -1
	}
	return bytes.Compare(a.Key[:], b.Key[:])
}

// Whether record a supersedes b, both of one key: the higher version, and at one version a tombstone, so a tie never
// shows a deleted document.
func searchVersionSupersedes(a *SearchVersionRecord, b *SearchVersionRecord) bool {
	if a.Version != b.Version {
		return a.Version > b.Version
	}
	return a.Tombstone && !b.Tombstone
}

// A run's id under its root, which names its files.
type SearchVersionRunId uint64

// A fresh run id.
func newSearchVersionRunId() SearchVersionRunId {
	var buffer [8]byte
	for {
		rand.Read(buffer[:])
		// 0 is no run, and the top bit stays clear so the id prints as a small decimal
		if id := binary.BigEndian.Uint64(buffer[:]) >> 1; id != 0 {
			return SearchVersionRunId(id)
		}
	}
}

// A run's meta, its commit point.
type searchVersionMetaWire struct {
	Version   int    `json:"version"`
	Kind      int    `json:"kind"`
	StartDay  uint32 `json:"start_day,omitempty"`
	PageBytes int    `json:"page_bytes"`
	Pages     uint64 `json:"pages"`
	Root      uint64 `json:"root"`
	Levels    int    `json:"levels"`
	Records   uint64 `json:"records"`
	// the files ordinals index
	Files []searchVersionFileWire `json:"files"`
}

// One file of a run's table.
type searchVersionFileWire struct {
	Path    string `json:"path"`
	Version uint64 `json:"version"`
}

// One index root's version table in a ref's index cache. Construct with NewSearchVersionTable; the sync engine holds one
// a root, which counts the snapshots open on each run.
type SearchVersionTable struct {
	cache    *SearchCache
	repoId   Id
	refId    Id
	root     string
	settings *SidecarSearchSettings
	// pages a probe or merge read from the store, for tests: a probe that hits the page LRU reads none
	pageReadCount atomic.Uint64
	// the most a merge pass held, its inputs' bytes and its writer's, since the table was made
	mergeHeldMax atomic.Int64

	stateLock sync.Mutex
	// open snapshots on each run
	holds map[SearchVersionRunId]int
	// runs retired while held, removed when the last snapshot on them closes
	retired map[SearchVersionRunId]bool
}

// The version table of root, an index root's path, in cache's ref.
func NewSearchVersionTable(cache *SearchCache, repoId Id, refId Id, root string) (*SearchVersionTable, error) {
	if cache == nil || repoId == (Id{}) || refId == (Id{}) || root == "" || strings.IndexByte(root, 0) != -1 {
		return nil, fmt.Errorf("%w: a table needs its cache, ref and root", ErrSearchVersionArgs)
	}
	settings := cache.settings
	if settings.VersionPageByteCount < searchVersionPageHeaderByteCount+2*searchVersionEntryMaxByteCount ||
		settings.VersionPageByteCount > math.MaxUint16 || settings.VersionMergeInputCount < 2 || settings.VersionMergeByteCount <= 0 {
		return nil, fmt.Errorf("%w: the table's settings", ErrSearchVersionArgs)
	}
	return &SearchVersionTable{
		cache:    cache,
		repoId:   repoId,
		refId:    refId,
		root:     root,
		settings: settings,
		holds:    map[SearchVersionRunId]int{},
		retired:  map[SearchVersionRunId]bool{},
	}, nil
}

// A run's cache key: the root's path, at the run's id.
func (self *SearchVersionTable) runKey(runId SearchVersionRunId) SearchCacheKey {
	return SearchCacheKey{RepoId: self.repoId, RefId: self.refId, Path: self.root, Version: uint64(runId)}
}

// A run's directory in the cache's store.
func (self *SearchVersionTable) runBase(runId SearchVersionRunId) string {
	return searchCachePartName(self.runKey(runId), string(SearchCachePartVersionTable))
}

// The runs of this root on the medium, whole (their meta written) or not.
func (self *SearchVersionTable) RunIds() ([]SearchVersionRunId, error) {
	prefix := searchCacheRefName(self.repoId, self.refId) + "/p" + hex.EncodeToString([]byte(self.root)) + "/"
	entries, err := self.cache.store.List(prefix)
	if err != nil {
		return nil, err
	}
	runIds := []SearchVersionRunId{}
	for _, entry := range entries {
		rest := strings.TrimPrefix(entry.Name, prefix)
		version, part, ok := strings.Cut(rest, "/")
		if !ok || !strings.HasPrefix(part, string(SearchCachePartVersionTable)+"/") {
			continue
		}
		id, err := strconv.ParseUint(version, 10, 64)
		if err != nil || id == 0 {
			continue
		}
		if runId := SearchVersionRunId(id); !slices.Contains(runIds, runId) {
			runIds = append(runIds, runId)
		}
	}
	slices.Sort(runIds)
	return runIds, nil
}

// A run as a reader holds it: its meta.
type searchVersionRun struct {
	id   SearchVersionRunId
	slot SearchVersionSlot
	meta *searchVersionMetaWire
}

// Reads a run's meta, through the decoded LRU: ErrSidecarStoreAbsent for a run never committed, ErrSearchCacheRefetch
// for one that failed, which is dropped.
func (self *SearchVersionTable) openRun(runId SearchVersionRunId) (*searchVersionRun, error) {
	base := self.runBase(runId)
	value, err := self.cache.Decoded(SearchDecodedKey{Key: self.runKey(runId), Part: string(SearchCachePartVersionTable)}, func() (any, int64, error) {
		content, err := self.cache.readSmall(base+"/"+searchCacheMetaName, searchCacheMetaMax)
		if err != nil {
			return nil, 0, err
		}
		meta := &searchVersionMetaWire{}
		if json.Unmarshal(content, meta) != nil || meta.Version != searchVersionMetaVersion || meta.PageBytes != self.settings.VersionPageByteCount ||
			meta.Pages == 0 || meta.Root >= meta.Pages || meta.Levels < 1 {
			return nil, 0, fmt.Errorf("%w: a version run's meta", ErrSidecarStoreFailed)
		}
		slot := SearchVersionSlot{Kind: SearchVersionSlotKind(meta.Kind), StartDay: meta.StartDay}
		if slot.check() != nil {
			return nil, 0, fmt.Errorf("%w: a version run's slot", ErrSidecarStoreFailed)
		}
		run := &searchVersionRun{id: runId, slot: slot, meta: meta}
		return run, int64(len(content)), nil
	})
	if err != nil {
		if errors.Is(err, ErrSidecarStoreAbsent) {
			return nil, ErrSidecarStoreAbsent
		}
		return nil, self.runFailed(runId, err)
	}
	return value.(*searchVersionRun), nil
}

// A run's read failed: one that failed AEAD or decoding, or lost a page, is dropped and answered ErrSearchCacheRefetch;
// a lock is answered as it is.
func (self *SearchVersionTable) runFailed(runId SearchVersionRunId, err error) error {
	if !isSearchCacheDamage(err) {
		return err
	}
	self.cache.log.Warningf("[search]a version table run failed: dropped, to build again")
	if dropErr := self.removeRun(runId); dropErr != nil {
		return dropErr
	}
	return ErrSearchCacheRefetch
}

// Removes a run's files, meta first, and its decoded pages.
func (self *SearchVersionTable) removeRun(runId SearchVersionRunId) error {
	base := self.runBase(runId)
	self.cache.operationLock.Lock()
	defer self.cache.operationLock.Unlock()
	if err := self.cache.removeUnder(base); err != nil {
		return err
	}
	self.cache.decoded.dropPrefix(base)
	self.cache.versionPages.dropPrefix(base)
	return nil
}

// Page index of run, through the version-page LRU (Search.VersionCacheByteCount): one sealed 4 KiB file opened on a miss.
func (self *SearchVersionTable) page(run *searchVersionRun, index uint64) ([]byte, error) {
	if run.meta.Pages <= index {
		return nil, fmt.Errorf("%w: a page past its run", ErrSidecarStoreFailed)
	}
	base := self.runBase(run.id)
	value, err := self.cache.VersionPage(SearchDecodedKey{Key: self.runKey(run.id), Part: string(SearchCachePartVersionTable), Item: index}, func() (any, int64, error) {
		self.pageReadCount.Add(1)
		content, err := self.cache.readSmall(base+"/"+strconv.FormatUint(index, 10), self.settings.VersionPageByteCount)
		if err != nil {
			return nil, 0, err
		}
		if len(content) != self.settings.VersionPageByteCount {
			return nil, 0, fmt.Errorf("%w: a page of the wrong size", ErrSidecarStoreFailed)
		}
		return content, int64(len(content)), nil
	})
	if err != nil {
		return nil, self.runFailed(run.id, err)
	}
	return value.([]byte), nil
}

// One decoded entry of a page.
type searchVersionEntry struct {
	class   byte
	key     [indexIdByteCount]byte
	version uint64
	flags   byte
	// a data entry's file ordinal, an index entry's child page
	value uint64
}

// The entry at the start of src, and its length; an error for one that breaks the format.
func decodeSearchVersionEntry(src []byte, data bool) (searchVersionEntry, int, error) {
	entry := searchVersionEntry{}
	if len(src) < 1+indexIdByteCount {
		return entry, 0, fmt.Errorf("%w: a short version entry", ErrSidecarStoreFailed)
	}
	entry.class = src[0]
	if entry.class != searchVersionClassDocument && entry.class != searchVersionClassRef {
		return entry, 0, fmt.Errorf("%w: a version entry's class", ErrSidecarStoreFailed)
	}
	copy(entry.key[:], src[1:1+indexIdByteCount])
	at := 1 + indexIdByteCount
	if data {
		version, length := binary.Uvarint(src[at:])
		if length <= 0 || length != len(binary.AppendUvarint(nil, version)) {
			return entry, 0, fmt.Errorf("%w: a version entry's version", ErrSidecarStoreFailed)
		}
		entry.version = version
		at += length
		if len(src) <= at {
			return entry, 0, fmt.Errorf("%w: a version entry's flags", ErrSidecarStoreFailed)
		}
		entry.flags = src[at]
		if entry.flags&^searchVersionFlagTombstone != 0 {
			return entry, 0, fmt.Errorf("%w: a version entry's flags", ErrSidecarStoreFailed)
		}
		at += 1
	}
	value, length := binary.Uvarint(src[at:])
	if length <= 0 || length != len(binary.AppendUvarint(nil, value)) {
		return entry, 0, fmt.Errorf("%w: a version entry's value", ErrSidecarStoreFailed)
	}
	entry.value = value
	return entry, at + length, nil
}

// The order of an entry against a probed (class, key).
func compareSearchVersionEntry(entry *searchVersionEntry, class byte, key *[indexIdByteCount]byte) int {
	if entry.class != class {
		if entry.class < class {
			return -1
		}
		return 1
	}
	return bytes.Compare(entry.key[:], key[:])
}

// Walks a page's entries in order, stopping when visit answers false.
func walkSearchVersionPage(page []byte, wantKind byte, visit func(entry *searchVersionEntry) bool) error {
	if len(page) < searchVersionPageHeaderByteCount || page[0] != wantKind {
		return fmt.Errorf("%w: a version page of the wrong kind", ErrSidecarStoreFailed)
	}
	count := int(binary.BigEndian.Uint16(page[1:3]))
	at := searchVersionPageHeaderByteCount
	for range count {
		entry, length, err := decodeSearchVersionEntry(page[at:], wantKind == searchVersionPageData)
		if err != nil {
			return err
		}
		at += length
		if !visit(&entry) {
			return nil
		}
	}
	return nil
}

// The record run holds for (class, key): one page a level, root first. Found false where it holds none.
func (self *SearchVersionTable) lookup(run *searchVersionRun, class byte, key *[indexIdByteCount]byte) (SearchVersionRecord, bool, error) {
	index := run.meta.Root
	for level := run.meta.Levels; 1 < level; level -= 1 {
		page, err := self.page(run, index)
		if err != nil {
			return SearchVersionRecord{}, false, err
		}
		// the last child whose first key is at or below the key; before the first, none holds it
		child, found := uint64(0), false
		if err := walkSearchVersionPage(page, searchVersionPageIndex, func(entry *searchVersionEntry) bool {
			if 0 < compareSearchVersionEntry(entry, class, key) {
				return false
			}
			child, found = entry.value, true
			return true
		}); err != nil {
			return SearchVersionRecord{}, false, self.runFailed(run.id, err)
		}
		if !found {
			return SearchVersionRecord{}, false, nil
		}
		index = child
	}
	page, err := self.page(run, index)
	if err != nil {
		return SearchVersionRecord{}, false, err
	}
	record, found := SearchVersionRecord{}, false
	var fileErr error
	if err := walkSearchVersionPage(page, searchVersionPageData, func(entry *searchVersionEntry) bool {
		switch compare := compareSearchVersionEntry(entry, class, key); {
		case compare < 0:
			return true
		case 0 < compare:
			return false
		}
		if uint64(len(run.meta.Files)) <= entry.value {
			fileErr = fmt.Errorf("%w: a version entry's file", ErrSidecarStoreFailed)
			return false
		}
		file := run.meta.Files[entry.value]
		record = SearchVersionRecord{
			Key:          entry.key,
			RefTombstone: entry.class == searchVersionClassRef,
			Version:      entry.version,
			Tombstone:    entry.flags&searchVersionFlagTombstone != 0 && entry.class == searchVersionClassDocument,
			File:         SearchVersionFile{Path: file.Path, Version: file.Version},
		}
		found = true
		return false
	}); err != nil {
		return SearchVersionRecord{}, false, self.runFailed(run.id, err)
	}
	if fileErr != nil {
		return SearchVersionRecord{}, false, self.runFailed(run.id, fileErr)
	}
	return record, found, nil
}

// The runs a search reads, held open from Snapshot to Close so no retirement removes one under it.
type SearchVersionSnapshot struct {
	table *SearchVersionTable
	runs  []*searchVersionRun
	once  sync.Once
}

// Opens the runs runIds name, the ones a manifest names, as a snapshot: each must be whole. A run that is absent or
// fails is an error, and nothing is held.
func (self *SearchVersionTable) Snapshot(runIds []SearchVersionRunId) (*SearchVersionSnapshot, error) {
	runs := []*searchVersionRun{}
	for _, runId := range runIds {
		run, err := self.openRun(runId)
		if err != nil {
			return nil, err
		}
		runs = append(runs, run)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for _, run := range runs {
		self.holds[run.id] += 1
	}
	return &SearchVersionSnapshot{table: self, runs: runs}, nil
}

// Releases the snapshot's runs; a run retired meanwhile goes once the last snapshot on it closes. Safe to call again.
func (self *SearchVersionSnapshot) Close() {
	self.once.Do(func() {
		table := self.table
		released := []SearchVersionRunId{}
		func() {
			table.stateLock.Lock()
			defer table.stateLock.Unlock()
			for _, run := range self.runs {
				table.holds[run.id] -= 1
				if table.holds[run.id] <= 0 {
					delete(table.holds, run.id)
					if table.retired[run.id] {
						delete(table.retired, run.id)
						released = append(released, run.id)
					}
				}
			}
		}()
		for _, runId := range released {
			if err := table.removeRun(runId); err != nil {
				table.cache.log.Warningf("[search]a retired version run was not removed: %s", err)
			}
		}
	})
}

// What a probe found for one candidate's key (§11.14's newest row).
type SearchVersionProbe struct {
	// Whether any run holds the doc key.
	Found bool
	// The doc key's highest version over every run, whether that version is a tombstone in any of them, and the file
	// and slot of the run holding it.
	Version   uint64
	Tombstone bool
	File      SearchVersionFile
	Slot      SearchVersionSlot
	// The highest ref tombstone of the probed ref id: rows of that ref below it are gone. 0 for none.
	RefTombstoneVersion uint64
	// The version the key is masked at and below by erased runs: SearchVersionErasedAll under an ERASE; 0 for none.
	ErasedThrough uint64
}

// Whether a candidate at version is current (§11.14's newest row, D-EVS-52): the doc key's highest version over every
// partition held, not a tombstone, no ref tombstone of its ref above it (a ref DELETE's tombstone sits above every
// version of the ref's documents, §11.14's companion row), and not erased at or above it. Equal versions in two
// partitions are one content, so whichever partition the candidate came from counts.
func (self SearchVersionProbe) Current(version uint64) bool {
	return self.Found && self.Version == version && !self.Tombstone && self.RefTombstoneVersion <= version &&
		self.ErasedThrough < version
}

// Probes the snapshot for one candidate: its doc key, and its ref id where the index is ur/index's (a row's ref_id), nil
// in a file-mode ref's. One page a level of each run, through the page LRU; nothing of the runs is collected. An error
// is a run that failed, which was dropped: the caller masks the candidate.
func (self *SearchVersionSnapshot) Probe(docKey [indexIdByteCount]byte, refId *Id) (SearchVersionProbe, error) {
	probe := SearchVersionProbe{}
	newest := SearchVersionRecord{}
	for _, run := range self.runs {
		if run.slot.Kind == SearchVersionErased {
			erased, found, err := self.table.lookup(run, searchVersionClassDocument, &docKey)
			if err != nil {
				return SearchVersionProbe{}, err
			}
			if found {
				probe.ErasedThrough = max(probe.ErasedThrough, erased.Version)
			}
			continue
		}
		record, found, err := self.table.lookup(run, searchVersionClassDocument, &docKey)
		if err != nil {
			return SearchVersionProbe{}, err
		}
		if found && (!probe.Found || searchVersionSupersedes(&record, &newest)) {
			newest = record
			probe.Found = true
			probe.Slot = run.slot
		}
		if refId != nil {
			refKey := [indexIdByteCount]byte(*refId)
			refRecord, found, err := self.table.lookup(run, searchVersionClassRef, &refKey)
			if err != nil {
				return SearchVersionProbe{}, err
			}
			if found {
				probe.RefTombstoneVersion = max(probe.RefTombstoneVersion, refRecord.Version)
			}
		}
	}
	if probe.Found {
		probe.Version = newest.Version
		probe.Tombstone = newest.Tombstone
		probe.File = newest.File
	}
	return probe, nil
}

// Probes runIds' runs for one candidate, opening and closing a snapshot around it: for a caller holding no snapshot.
func (self *SearchVersionTable) Probe(runIds []SearchVersionRunId, docKey [indexIdByteCount]byte, refId *Id) (SearchVersionProbe, error) {
	snapshot, err := self.Snapshot(runIds)
	if err != nil {
		return SearchVersionProbe{}, err
	}
	defer snapshot.Close()
	return snapshot.Probe(docKey, refId)
}

// Removes every run of this root that keep does not name: what no manifest, plan or open snapshot names any more
// (DESIGN-DETAILS 7.2.7's retire step). A run an open snapshot holds goes when the last one closes.
func (self *SearchVersionTable) Retire(keep []SearchVersionRunId) error {
	runIds, err := self.RunIds()
	if err != nil {
		return err
	}
	for _, runId := range runIds {
		if slices.Contains(keep, runId) {
			continue
		}
		held := func() bool {
			self.stateLock.Lock()
			defer self.stateLock.Unlock()
			if 0 < self.holds[runId] {
				self.retired[runId] = true
				return true
			}
			return false
		}()
		if held {
			continue
		}
		if err := self.removeRun(runId); err != nil {
			return err
		}
	}
	return nil
}

// The pages read from the store so far: what a probe that hit the page LRU did not add to.
func (self *SearchVersionTable) PageReadCount() uint64 {
	return self.pageReadCount.Load()
}

// The most one merge pass of this table has held: its open inputs' bytes and its writer's, which
// Search.VersionMergeByteCount bounds.
func (self *SearchVersionTable) MergeHeldMax() int64 {
	return self.mergeHeldMax.Load()
}
