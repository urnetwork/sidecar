//go:build !ios_extension

// The local layer (§11.14's coverage row; §16.10's phase 1 and coverage rows; §5.9's holds row; D-EVS-49; FI-18; FS-74;
// DESIGN-DETAILS 7.2.7; SEARCH-M10-25): what a host with the text indexes from its own plaintext for every document
// whose newest version no validated index file holds, a content version past indexed_through first among them, so a
// commit is searchable here at once rather than when its writer's push or a backfill covers it. A bad file's documents
// join it the same way (7.2.7: a bad file holds nothing for search), which lets a host with a bad file serve from text
// again. It is searched in phase 1 beside the buckets as partition local, and joins newest-wins: its version of a key
// supersedes the index's older ones, and once a validated file holds that version or newer the index's copy answers
// and the local one goes at the next swap (Cover). A removal or a version that turns binary or skipped is a tombstone
// here as in the index, so the index's older entry is masked meanwhile; a version with fewer chunks than the one it
// replaces tombstones the chunks past its own.
//
// The device's own journal of committed documents not yet in a companion push (SEARCH-M10-14's IndexJournal) joins it
// through searchLocalJournal: its entries are searched and masked as the layer's are. An erasure reaches both: the
// layer drops an erased document's entries at once (Erase, which CORE-M10-04's ApplyErase and ApplyCut call), and the
// version table masks them meanwhile.
//
// Its entries are sealed as derived data (SearchCachePartLocalLayer), each in the slot entry codec, so the layer is
// rebuilt from storage after a restart, and are held in memory within LocalLayerByteCount: a version past it is left
// out and counted, and coverage reports it not yet searchable rather than hiding it. Safe for concurrent use.

package sidecar

import (
	"context"
	"fmt"
	"slices"
	"sync"
)

// The sealed local layer's format.
const searchLocalLayerFormat = 1

// The device's journal of its own committed documents not yet pushed, as the local layer reads it (SEARCH-M10-14's
// IndexJournal implements it when it lands). Safe for concurrent use.
type searchLocalJournal interface {
	// Visits each journaled entry of the index root, a full entry or a tombstone as its companion push will carry it.
	searchJournalEntries(visit func(entry *indexEntry) error) error
}

// What a local layer is of.
type SearchLocalLayerArgs struct {
	RepoId Id
	// The ref whose index this is: a file-mode ref, or ur/index for a companion index, whose rows name their refs.
	RefId     Id
	Companion bool
	// K_ref, which doc keys derive from (indexRefKey).
	RefKey   []byte
	Settings *SearchResultSettings
	// Extractor 1's and the slot codec's bounds; nil takes DefaultIndexFormatSettings.
	FormatSettings *IndexFormatSettings
}

// One content version this host's text holds past what the index covers.
type SearchLocalVersion struct {
	// The content ref the version is on: the layer's own for an in-ref index.
	RefId   Id
	Path    []byte
	Version uint64
	// The push's signed time, ms: the entries' time, as the writer's would be.
	TimeMs int64
	// The version's documents, one a chunk, as SearchTextSource gives them; none where the path was removed, or the
	// version is binary or outside what §11.14's never row indexes.
	Documents []*IndexDocument
	// The chunks the version this one replaces held: those past this version's own are tombstoned.
	ReplacedChunkCount uint32
}

// A host's local layer for one index root.
type SearchLocalLayer struct {
	args    *SearchLocalLayerArgs
	journal searchLocalJournal

	stateLock sync.Mutex
	entries   map[[indexIdByteCount]byte]*indexEntry
	byteCount int64
	// Versions LocalLayerByteCount left out.
	uncoveredCount int
}

// An empty layer for args.
func NewSearchLocalLayer(args *SearchLocalLayerArgs) (*SearchLocalLayer, error) {
	if args == nil || args.RepoId == (Id{}) || args.RefId == (Id{}) || len(args.RefKey) == 0 {
		return nil, fmt.Errorf("%w: a local layer names its repo, ref and key", ErrSearchCacheArgs)
	}
	settings := *args
	if settings.Settings == nil {
		settings.Settings = DefaultSearchResultSettings()
	}
	if err := settings.Settings.check(); err != nil {
		return nil, err
	}
	if settings.FormatSettings == nil {
		settings.FormatSettings = DefaultIndexFormatSettings()
	}
	return &SearchLocalLayer{args: &settings, entries: map[[indexIdByteCount]byte]*indexEntry{}}, nil
}

// Joins the device's journal, nil leaving it out.
func (self *SearchLocalLayer) setJournal(journal searchLocalJournal) {
	self.journal = journal
}

// The entries a version makes: each document's full entry, a tombstone for a skipped chunk, and tombstones for the
// chunks the replaced version held past this one's, or for each of its chunks where the path was removed.
func (self *SearchLocalLayer) entriesOf(normalizer *indexNormalizer, version *SearchLocalVersion) ([]*indexEntry, error) {
	refId := version.RefId
	if !self.args.Companion {
		refId = self.args.RefId
	}
	timeSeconds := indexEntrySeconds(version.TimeMs)
	tombstone := func(chunk uint32) (*indexEntry, error) {
		key, err := indexDocKey(self.args.RefKey, refId, version.Path, chunk)
		if err != nil {
			return nil, err
		}
		return &indexEntry{kind: indexEntryTombstone, key: key, version: version.Version, timeSeconds: timeSeconds}, nil
	}
	entries := []*indexEntry{}
	for _, document := range version.Documents {
		key, err := indexDocKey(self.args.RefKey, refId, version.Path, document.Chunk)
		if err != nil {
			return nil, err
		}
		prepared, err := document.prepare(normalizer, self.args.Companion, refId, self.args.FormatSettings)
		if err != nil {
			return nil, err
		}
		if prepared.skipped {
			entry, err := tombstone(document.Chunk)
			if err != nil {
				return nil, err
			}
			entries = append(entries, entry)
			continue
		}
		entries = append(entries, &indexEntry{kind: indexEntryFull, key: key, version: version.Version, timeSeconds: timeSeconds, row: prepared.row, keys: prepared.keys})
	}
	// a removed, binary or excluded version leaves no chunk of its path, the first at least
	tombstoneEnd := version.ReplacedChunkCount
	if len(version.Documents) == 0 {
		tombstoneEnd = max(tombstoneEnd, 1)
	}
	for chunk := uint32(len(version.Documents)); chunk < tombstoneEnd; chunk += 1 {
		entry, err := tombstone(chunk)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// Indexes one version from this host's text. An entry below one the layer holds for its key is left out; one past the
// layer's memory bound is counted and reads not yet searchable, and the older entry of its key it would have replaced
// goes, so the layer never offers a version it knows is not the newest.
func (self *SearchLocalLayer) Index(normalizer *indexNormalizer, version *SearchLocalVersion) error {
	entries, err := self.entriesOf(normalizer, version)
	if err != nil {
		return err
	}
	encoded := make([][]byte, len(entries))
	for index, entry := range entries {
		if encoded[index], err = entry.appendEncoded(nil, self.args.Companion, self.args.FormatSettings); err != nil {
			return err
		}
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	for index, entry := range entries {
		held, ok := self.entries[entry.key]
		if ok && entry.version <= held.version {
			continue
		}
		heldByteCount := int64(0)
		if ok {
			heldByteCount = searchLocalEntryByteCount(held, self.args.Companion, self.args.FormatSettings)
		}
		if self.args.Settings.LocalLayerByteCount < self.byteCount-heldByteCount+int64(len(encoded[index])) {
			self.uncoveredCount += 1
			if ok {
				self.byteCount -= heldByteCount
				delete(self.entries, entry.key)
			}
			continue
		}
		self.entries[entry.key] = entry
		self.byteCount += int64(len(encoded[index])) - heldByteCount
	}
	return nil
}

// An entry's encoded size, which the memory bound counts.
func searchLocalEntryByteCount(entry *indexEntry, companion bool, settings *IndexFormatSettings) int64 {
	encoded, err := entry.appendEncoded(nil, companion, settings)
	if err != nil {
		return 0
	}
	return int64(len(encoded))
}

// Drops the layer's entry of key where its version is at or below throughVersion: an ERASE (searchErasedAll) or a
// listing in the erasure set. Whether one went.
func (self *SearchLocalLayer) Erase(key [indexIdByteCount]byte, throughVersion uint64) bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	entry, ok := self.entries[key]
	if !ok || throughVersion < entry.version {
		return false
	}
	self.byteCount -= searchLocalEntryByteCount(entry, self.args.Companion, self.args.FormatSettings)
	delete(self.entries, key)
	return true
}

// Drops every entry the index now covers, a validated file holding its version or newer, or that the table holds as
// erased: at each swap (SEARCH-M10-19's), whose table it probes. The entries dropped.
func (self *SearchLocalLayer) Cover(probe searchVersionProbe) (int, error) {
	if probe == nil {
		return 0, errSearchMaskNoTable
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	dropped := 0
	for key, entry := range self.entries {
		record, err := probe(key)
		if err != nil {
			return dropped, err
		}
		if record.found && entry.version <= record.version || entry.version <= record.erasedThrough {
			self.byteCount -= searchLocalEntryByteCount(entry, self.args.Companion, self.args.FormatSettings)
			delete(self.entries, key)
			dropped += 1
		}
	}
	return dropped, nil
}

// Versions the memory bound left out, which coverage reports not yet searchable.
func (self *SearchLocalLayer) Uncovered() int {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.uncoveredCount
}

// The layer's entries with the journal's, the newest of each key, ascending by key and kind.
func (self *SearchLocalLayer) joined() ([]*indexEntry, error) {
	newest := map[[indexIdByteCount]byte]*indexEntry{}
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for key, entry := range self.entries {
			newest[key] = entry
		}
	}()
	if self.journal != nil {
		if err := self.journal.searchJournalEntries(func(entry *indexEntry) error {
			if held, ok := newest[entry.key]; !ok || held.version < entry.version {
				newest[entry.key] = entry
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	entries := []*indexEntry{}
	for _, entry := range newest {
		entries = append(entries, entry)
	}
	slices.SortFunc(entries, indexCompareEntries)
	return entries, nil
}

// The newest entry the layer or the journal holds of key, a tombstone included: the mask's local probe.
func (self *SearchLocalLayer) newest(key [indexIdByteCount]byte) (uint64, bool, bool) {
	version, tombstone, found := uint64(0), false, false
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if entry, ok := self.entries[key]; ok {
			version, tombstone, found = entry.version, entry.kind != indexEntryFull, true
		}
	}()
	if self.journal != nil {
		_ = self.journal.searchJournalEntries(func(entry *indexEntry) error {
			if entry.key == key && (!found || version < entry.version) {
				version, tombstone, found = entry.version, entry.kind != indexEntryFull, true
			}
			return nil
		})
	}
	return version, tombstone, found
}

// The layer as a partition a search matches: one head of its entries, scanned per document as a writer's head is.
func (self *SearchLocalLayer) partition() (*searchPartitionSource, error) {
	entries, err := self.joined()
	if err != nil {
		return nil, err
	}
	return &searchPartitionSource{
		partition:      searchPartitionLocal,
		slots:          []*searchSlotSource{{slot: &indexSlot{entries: entries}, head: true, path: "local"}},
		formatSettings: self.args.FormatSettings,
	}, nil
}

// The layer's bytes: its format, its left-out count, its entry count, then each entry in the slot codec, ascending by
// key. Only the layer's own entries: the journal keeps its own.
func (self *SearchLocalLayer) encode() ([]byte, error) {
	entries := []*indexEntry{}
	uncoveredCount := 0
	func() {
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		for _, entry := range self.entries {
			entries = append(entries, entry)
		}
		uncoveredCount = self.uncoveredCount
	}()
	slices.SortFunc(entries, indexCompareEntries)
	encoded := []byte{searchLocalLayerFormat}
	encoded = indexAppendVByte(encoded, uint64(uncoveredCount))
	encoded = indexAppendVByte(encoded, uint64(len(entries)))
	for _, entry := range entries {
		var err error
		if encoded, err = entry.appendEncoded(encoded, self.args.Companion, self.args.FormatSettings); err != nil {
			return nil, err
		}
	}
	return encoded, nil
}

// Replaces the layer's entries with those encoded, refusing what encode would not write.
func (self *SearchLocalLayer) decode(encoded []byte) error {
	decoder := indexDecoder{src: encoded}
	if format := decoder.oneByte(); decoder.err == nil && format != searchLocalLayerFormat {
		return fmt.Errorf("%w: a local layer of format %d", ErrSearchCacheArgs, format)
	}
	uncoveredCount := decoder.vbyte()
	entryCount := decoder.vbyte()
	if decoder.err != nil || uint64(decoder.remaining()) < entryCount {
		return fmt.Errorf("%w: a local layer's counts", ErrSearchCacheArgs)
	}
	entries := map[[indexIdByteCount]byte]*indexEntry{}
	byteCount := int64(0)
	var previous *indexEntry
	for range entryCount {
		start := decoder.remaining()
		entry := decoder.entry(self.args.Companion, self.args.FormatSettings)
		if decoder.err != nil {
			return decoder.err
		}
		if entry.kind == indexEntryDiff || previous != nil && indexCompareEntries(previous, entry) >= 0 || entries[entry.key] != nil {
			return fmt.Errorf("%w: a local layer's entries out of order, repeated or diffs", ErrSearchCacheArgs)
		}
		previous = entry
		entries[entry.key] = entry
		byteCount += int64(start - decoder.remaining())
	}
	if decoder.remaining() != 0 {
		return fmt.Errorf("%w: bytes after a local layer", ErrSearchCacheArgs)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.entries = entries
	self.byteCount = byteCount
	self.uncoveredCount = int(uncoveredCount)
	return nil
}

// Seals the layer as the derived part at key, replacing the copy kept there, so an entry an erasure dropped is in no
// kept copy. Version 0 keeps one copy a root.
func (self *SearchLocalLayer) Save(ctx context.Context, cache *SearchCache, key SearchCacheKey) error {
	encoded, err := self.encode()
	if err != nil {
		return err
	}
	return cache.PutDerived(ctx, &SearchCacheDerived{Key: key, Part: SearchCachePartLocalLayer, Plaintext: encoded})
}

// Reads the layer kept at key, leaving it empty where none is.
func (self *SearchLocalLayer) Load(cache *SearchCache, key SearchCacheKey) error {
	frames, err := cache.OpenDerived(key, SearchCachePartLocalLayer)
	if err == ErrSidecarStoreAbsent {
		return nil
	}
	if err != nil {
		return err
	}
	encoded, err := frames.ReadAll()
	if err != nil {
		return err
	}
	return self.decode(encoded)
}
