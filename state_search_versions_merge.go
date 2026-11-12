//go:build !ios_extension

// The version table's merge (CORE-M10-02; §5.9's versions row): a run is built by a streaming merge of key-ordered
// inputs, at most Search.VersionMergeInputCount (16) open at once and Search.VersionMergeByteCount (1 MiB) held in all,
// the inputs' own buffers counted with the merge's. More inputs than one pass takes merge into intermediate runs, which
// merge in turn and go once the run is whole. Each key keeps the record that supersedes the rest: the higher version,
// and at one version a tombstone. Pages are written to the cache as they fill, and the index above them a page a level,
// so nothing of the run is held whole (QD-641); the meta is written last, the run's commit point.
//
// Inputs: a shard's doc and tombstone tables, read by frame through its reader; a sealed slot's, head's or large
// entry's entries, which carry doc keys and ref ids in one order and are sorted in memory, a slot being at most a few
// KiB; an earlier run's pages; and records a caller lists, such as an erasure's keys.

package sidecar

import (
	"container/heap"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strconv"
	"unsafe"
)

// A key-ordered source of records for a merge, opened when a pass takes it.
type SearchVersionSource interface {
	Open() (SearchVersionInput, error)
}

// An open source: its records ascending by (class, key), one a key, and the memory it holds while open.
type SearchVersionInput interface {
	// The next record; false at the end.
	Next() (SearchVersionRecord, bool, error)
	// The bytes it holds while open, which the merge counts against Search.VersionMergeByteCount.
	ByteCount() int64
	Close()
}

// One open input in the merge's heap, with its next record.
type searchVersionCursor struct {
	input  SearchVersionInput
	record SearchVersionRecord
	// whether record holds one yet, so the next is checked against it
	started bool
	index   int
}

// A min-heap of cursors by their next record's key, then their order, so ties pop in input order.
type searchVersionHeap []*searchVersionCursor

// heap.Interface: the cursors still holding a record.
func (self searchVersionHeap) Len() int {
	return len(self)
}

// heap.Interface: by the cursors' next keys, then their order.
func (self searchVersionHeap) Less(i int, j int) bool {
	if compare := compareSearchVersionRecords(&self[i].record, &self[j].record); compare != 0 {
		return compare < 0
	}
	return self[i].index < self[j].index
}

// heap.Interface.
func (self searchVersionHeap) Swap(i int, j int) {
	self[i], self[j] = self[j], self[i]
}

// heap.Interface: adds a cursor.
func (self *searchVersionHeap) Push(value any) {
	*self = append(*self, value.(*searchVersionCursor))
}

// heap.Interface: takes the last cursor off.
func (self *searchVersionHeap) Pop() any {
	old := *self
	cursor := old[len(old)-1]
	*self = old[:len(old)-1]
	return cursor
}

// The bytes the merge holds for one cursor in its heap.
var searchVersionCursorByteCount = int64(unsafe.Sizeof(searchVersionCursor{}))

// Builds slot's run from sources and answers its id. No source is held open past its pass; on an error every input is
// closed and nothing of the run, or of an intermediate, is left.
func (self *SearchVersionTable) Merge(ctx context.Context, slot SearchVersionSlot, sources []SearchVersionSource) (SearchVersionRunId, error) {
	if err := slot.check(); err != nil {
		return 0, err
	}
	if held, err := self.cache.Ref(self.repoId, self.refId); err != nil {
		return 0, err
	} else if held == nil {
		return 0, fmt.Errorf("%w: the cache follows no such ref", ErrSearchCacheUnnamed)
	}
	pending := slices.Clone(sources)
	intermediates := []SearchVersionRunId{}
	defer func() {
		for _, runId := range intermediates {
			if err := self.removeRun(runId); err != nil {
				self.cache.log.Warningf("[search]an intermediate version run was not removed: %s", err)
			}
		}
	}()
	for {
		if err := ctx.Err(); err != nil {
			return 0, err
		}
		inputs, taken, held, err := self.openPass(pending)
		if err != nil {
			return 0, err
		}
		final := taken == len(pending)
		runId, err := self.mergePass(ctx, slot, inputs, self.settings.VersionMergeByteCount-held)
		for _, input := range inputs {
			input.Close()
		}
		if err != nil {
			return 0, err
		}
		if final {
			return runId, nil
		}
		intermediates = append(intermediates, runId)
		pending = append(pending[taken:], &searchVersionRunSource{table: self, runId: runId})
	}
}

// Opens the first sources of pending that one pass takes: at most VersionMergeInputCount, while their bytes and the
// merge's own stay within VersionMergeByteCount. A pass of fewer than two inputs where more are pending makes no
// progress, and an input past the bound by itself can never be merged: both are refused, never run past the bound.
func (self *SearchVersionTable) openPass(pending []SearchVersionSource) ([]SearchVersionInput, int, int64, error) {
	inputs := []SearchVersionInput{}
	held := int64(self.levelReserve() * self.settings.VersionPageByteCount)
	closeAll := func() {
		for _, input := range inputs {
			input.Close()
		}
	}
	for _, source := range pending {
		if len(inputs) == self.settings.VersionMergeInputCount {
			break
		}
		input, err := source.Open()
		if err != nil {
			closeAll()
			return nil, 0, 0, err
		}
		next := held + input.ByteCount() + searchVersionCursorByteCount
		if self.settings.VersionMergeByteCount < next {
			input.Close()
			break
		}
		inputs = append(inputs, input)
		held = next
	}
	if len(inputs) == 0 && 0 < len(pending) {
		return nil, 0, 0, fmt.Errorf("%w: an input past the merge's bound by itself", ErrSearchVersionArgs)
	}
	if len(inputs) < 2 && len(inputs) < len(pending) {
		closeAll()
		return nil, 0, 0, fmt.Errorf("%w: two inputs past the merge's bound", ErrSearchVersionArgs)
	}
	for {
		peak := self.mergeHeldMax.Load()
		if held <= peak || self.mergeHeldMax.CompareAndSwap(peak, held) {
			break
		}
	}
	return inputs, len(inputs), held, nil
}

// The levels a run's tree may need, and so the pages a writer keeps, one a level: enough for a run of every page the
// cache could hold, at the fewest entries an index page of this size takes. A run never reaches it, since the cache's
// bound holds every run.
func (self *SearchVersionTable) levelReserve() int {
	pageByteCount := self.settings.VersionPageByteCount
	fanOut := float64((pageByteCount - searchVersionPageHeaderByteCount) / (1 + indexIdByteCount + indexVByteMaxByteCount))
	pages := float64(max(self.settings.CacheByteCount, self.settings.DesignatedCacheByteCount, self.settings.MemoryByteCount)/int64(pageByteCount) + 1)
	return 1 + int(math.Ceil(math.Log(pages)/math.Log(max(fanOut, 2))))
}

// Merges the open inputs into one run of slot, its file table within what the pass has left of its bound.
func (self *SearchVersionTable) mergePass(ctx context.Context, slot SearchVersionSlot, inputs []SearchVersionInput, fileByteCount int64) (SearchVersionRunId, error) {
	writer := self.newRunWriter(slot, fileByteCount)
	cursors := searchVersionHeap{}
	advance := func(cursor *searchVersionCursor) (bool, error) {
		previous := cursor.record
		record, ok, err := cursor.input.Next()
		if err != nil || !ok {
			return false, err
		}
		if cursor.started && compareSearchVersionRecords(&previous, &record) >= 0 {
			return false, fmt.Errorf("%w: an input out of key order", ErrSearchVersionArgs)
		}
		cursor.record = record
		cursor.started = true
		return true, nil
	}
	for index, input := range inputs {
		cursor := &searchVersionCursor{input: input, index: index}
		ok, err := advance(cursor)
		if err != nil {
			writer.abandon()
			return 0, err
		}
		if ok {
			cursors = append(cursors, cursor)
		}
	}
	heap.Init(&cursors)
	yield := newSidecarYield(self.cache.clock)
	for 0 < cursors.Len() {
		if err := ctx.Err(); err != nil {
			writer.abandon()
			return 0, err
		}
		best := cursors[0].record
		// every input's record of this key: the one that supersedes the rest is kept
		for 0 < cursors.Len() && compareSearchVersionRecords(&cursors[0].record, &best) == 0 {
			cursor := cursors[0]
			if searchVersionSupersedes(&cursor.record, &best) {
				best = cursor.record
			}
			ok, err := advance(cursor)
			if err != nil {
				writer.abandon()
				return 0, err
			}
			if ok {
				heap.Fix(&cursors, 0)
			} else {
				heap.Pop(&cursors)
			}
		}
		if err := writer.add(&best); err != nil {
			writer.abandon()
			return 0, err
		}
		yield.step()
	}
	return writer.commit()
}

// Writes one run, a page at a time.
type searchVersionRunWriter struct {
	table *SearchVersionTable
	runId SearchVersionRunId
	slot  SearchVersionSlot
	base  string
	// the page being filled at each level, 0 the data's, its entry count and first entry
	levels      [][]byte
	levelCounts []int
	levelFirsts [][1 + indexIdByteCount]byte
	// the pages flushed at each level
	levelPages []uint64
	nextPage   uint64
	records    uint64
	files      []searchVersionFileWire
	fileIndex  map[SearchVersionFile]uint64
	// what the file table holds, and the most it may: what the merge's bound left
	fileByteCount    int64
	fileMaxByteCount int64
	levelReserve     int
	last             *SearchVersionRecord
	failed           error
}

// A writer of a new run of slot, whose file table may hold fileMaxByteCount.
func (self *SearchVersionTable) newRunWriter(slot SearchVersionSlot, fileMaxByteCount int64) *searchVersionRunWriter {
	runId := newSearchVersionRunId()
	return &searchVersionRunWriter{
		table:            self,
		runId:            runId,
		slot:             slot,
		base:             self.runBase(runId),
		fileIndex:        map[SearchVersionFile]uint64{},
		fileMaxByteCount: fileMaxByteCount,
		levelReserve:     self.levelReserve(),
	}
}

// What one file of the table holds in memory: its entry, its key in the index and its path, twice.
func searchVersionFileByteCount(file SearchVersionFile) int64 {
	return int64(unsafe.Sizeof(searchVersionFileWire{})+unsafe.Sizeof(file)+unsafe.Sizeof(uint64(0))) + 2*int64(len(file.Path))
}

// An entry's class and key as one sort key.
func searchVersionEntryKey(record *SearchVersionRecord) [1 + indexIdByteCount]byte {
	key := [1 + indexIdByteCount]byte{}
	if record.RefTombstone {
		key[0] = searchVersionClassRef
	}
	copy(key[1:], record.Key[:])
	return key
}

// Appends one record, in key order, after the last.
func (self *searchVersionRunWriter) add(record *SearchVersionRecord) error {
	if self.failed != nil {
		return self.failed
	}
	if self.last != nil && compareSearchVersionRecords(self.last, record) >= 0 {
		return fmt.Errorf("%w: records out of key order", ErrSearchVersionArgs)
	}
	ordinal, ok := self.fileIndex[record.File]
	if !ok {
		self.fileByteCount += searchVersionFileByteCount(record.File)
		if self.fileMaxByteCount < self.fileByteCount {
			return fmt.Errorf("%w: a run of more files than the merge's bound holds", ErrSearchVersionArgs)
		}
		ordinal = uint64(len(self.files))
		self.files = append(self.files, searchVersionFileWire{Path: record.File.Path, Version: record.File.Version})
		self.fileIndex[record.File] = ordinal
	}
	key := searchVersionEntryKey(record)
	entry := make([]byte, 0, searchVersionEntryMaxByteCount)
	entry = append(entry, key[:]...)
	entry = binary.AppendUvarint(entry, record.Version)
	flags := byte(0)
	if record.Tombstone || record.RefTombstone {
		flags |= searchVersionFlagTombstone
	}
	entry = append(entry, flags)
	entry = binary.AppendUvarint(entry, ordinal)
	if err := self.append(0, key, entry); err != nil {
		self.failed = err
		return err
	}
	kept := *record
	self.last = &kept
	self.records += 1
	return nil
}

// Appends an entry to level's page, flushing the page first when it does not fit.
func (self *searchVersionRunWriter) append(level int, key [1 + indexIdByteCount]byte, entry []byte) error {
	if self.levelReserve <= level {
		return fmt.Errorf("%w: a run deeper than the cache could hold", ErrSearchVersionArgs)
	}
	for len(self.levels) <= level {
		page := make([]byte, searchVersionPageHeaderByteCount, self.table.settings.VersionPageByteCount)
		if len(self.levels) == 0 {
			page[0] = searchVersionPageData
		} else {
			page[0] = searchVersionPageIndex
		}
		self.levels = append(self.levels, page)
		self.levelCounts = append(self.levelCounts, 0)
		self.levelFirsts = append(self.levelFirsts, [1 + indexIdByteCount]byte{})
		self.levelPages = append(self.levelPages, 0)
	}
	if self.table.settings.VersionPageByteCount < len(self.levels[level])+len(entry) {
		if err := self.flush(level); err != nil {
			return err
		}
	}
	if self.levelCounts[level] == 0 {
		self.levelFirsts[level] = key
	}
	self.levels[level] = append(self.levels[level], entry...)
	self.levelCounts[level] += 1
	return nil
}

// Writes level's page, padded to its size, as the next page, and enters it in the level above.
func (self *searchVersionRunWriter) flush(level int) error {
	page := self.levels[level]
	binary.BigEndian.PutUint16(page[1:3], uint16(self.levelCounts[level]))
	padded := make([]byte, self.table.settings.VersionPageByteCount)
	copy(padded, page)
	pageNumber := self.nextPage
	if err := self.table.cache.writeSmall(self.base+"/"+strconv.FormatUint(pageNumber, 10), padded, false); err != nil {
		return err
	}
	self.nextPage += 1
	self.levelPages[level] += 1
	first := self.levelFirsts[level]
	self.levels[level] = self.levels[level][:searchVersionPageHeaderByteCount]
	self.levelCounts[level] = 0
	entry := make([]byte, 0, 1+indexIdByteCount+indexVByteMaxByteCount)
	entry = append(entry, first[:]...)
	entry = binary.AppendUvarint(entry, pageNumber)
	return self.append(level+1, first, entry)
}

// Flushes what is left bottom up until one page stands over the rest, then writes the meta: the run's commit point.
func (self *searchVersionRunWriter) commit() (SearchVersionRunId, error) {
	if self.failed != nil {
		self.abandon()
		return 0, self.failed
	}
	if len(self.levels) == 0 {
		// a run of no records: one empty data page
		page := make([]byte, searchVersionPageHeaderByteCount, self.table.settings.VersionPageByteCount)
		self.levels = append(self.levels, page)
		self.levelCounts = append(self.levelCounts, 0)
		self.levelFirsts = append(self.levelFirsts, [1 + indexIdByteCount]byte{})
		self.levelPages = append(self.levelPages, 0)
		if err := self.flush(0); err != nil {
			self.abandon()
			return 0, err
		}
	} else if 0 < self.levelCounts[0] {
		if err := self.flush(0); err != nil {
			self.abandon()
			return 0, err
		}
	}
	root, levels := uint64(0), 0
	for level := 1; ; level += 1 {
		if self.levelPages[level] == 0 && self.levelCounts[level] == 1 {
			// one child and nothing flushed beside it: that child is the root
			child, _ := binary.Uvarint(self.levels[level][searchVersionPageHeaderByteCount+1+indexIdByteCount:])
			root, levels = child, level
			break
		}
		if err := self.flush(level); err != nil {
			self.abandon()
			return 0, err
		}
	}
	meta, err := json.Marshal(&searchVersionMetaWire{
		Version:   searchVersionMetaVersion,
		Kind:      int(self.slot.Kind),
		StartDay:  self.slot.StartDay,
		PageBytes: self.table.settings.VersionPageByteCount,
		Pages:     self.nextPage,
		Root:      root,
		Levels:    levels,
		Records:   self.records,
		Files:     self.files,
	})
	if err != nil {
		self.abandon()
		return 0, err
	}
	if err := self.table.cache.writeSmall(self.base+"/"+searchCacheMetaName, meta, false); err != nil {
		self.abandon()
		return 0, err
	}
	return self.runId, nil
}

// Removes whatever of the run was written.
func (self *searchVersionRunWriter) abandon() {
	if err := self.table.removeRun(self.runId); err != nil {
		self.table.cache.log.Warningf("[search]an unfinished version run was not removed: %s", err)
	}
}

// A run's records in key order, read a data page at a time: an intermediate's, or any run's.
type searchVersionRunSource struct {
	table *SearchVersionTable
	runId SearchVersionRunId
}

// The run's records, a data page at a time. See SearchVersionSource.
func (self *searchVersionRunSource) Open() (SearchVersionInput, error) {
	run, err := self.table.openRun(self.runId)
	if err != nil {
		return nil, err
	}
	return &searchVersionRunInput{table: self.table, run: run}, nil
}

// A run being read in order: its data pages are the pages whose kind is data, in page order, which is key order.
type searchVersionRunInput struct {
	table    *SearchVersionTable
	run      *searchVersionRun
	next     uint64
	pending  []SearchVersionRecord
	consumed int
}

// The next record, reading the next data page when one runs out. See SearchVersionInput.
func (self *searchVersionRunInput) Next() (SearchVersionRecord, bool, error) {
	for self.consumed == len(self.pending) {
		if self.run.meta.Pages <= self.next {
			return SearchVersionRecord{}, false, nil
		}
		page, err := self.table.page(self.run, self.next)
		if err != nil {
			return SearchVersionRecord{}, false, err
		}
		self.next += 1
		self.pending = self.pending[:0]
		self.consumed = 0
		if page[0] != searchVersionPageData {
			continue
		}
		var fileErr error
		if err := walkSearchVersionPage(page, searchVersionPageData, func(entry *searchVersionEntry) bool {
			if uint64(len(self.run.meta.Files)) <= entry.value {
				fileErr = fmt.Errorf("%w: a version entry's file", ErrSidecarStoreFailed)
				return false
			}
			file := self.run.meta.Files[entry.value]
			self.pending = append(self.pending, SearchVersionRecord{
				Key:          entry.key,
				RefTombstone: entry.class == searchVersionClassRef,
				Version:      entry.version,
				Tombstone:    entry.flags&searchVersionFlagTombstone != 0 && entry.class == searchVersionClassDocument,
				File:         SearchVersionFile{Path: file.Path, Version: file.Version},
			})
			return true
		}); err != nil {
			return SearchVersionRecord{}, false, self.table.runFailed(self.run.id, err)
		}
		if fileErr != nil {
			return SearchVersionRecord{}, false, self.table.runFailed(self.run.id, fileErr)
		}
	}
	record := self.pending[self.consumed]
	self.consumed += 1
	return record, true, nil
}

// One page of records at a time.
func (self *searchVersionRunInput) ByteCount() int64 {
	return int64(2 * self.table.settings.VersionPageByteCount)
}

// Holds nothing to close: pages are read through the cache. See SearchVersionInput.
func (self *searchVersionRunInput) Close() {}

// Records a caller lists, sorted in memory, in place, at each Open: a slot's entries, an erasure's keys. Records of one
// key fold as they are read, the one that supersedes the rest kept. The list is the caller's, already in memory, so
// the merge counts nothing for it but its cursor.
type SearchVersionRecordsSource []SearchVersionRecord

// Sorts the list in place and reads it. See SearchVersionSource.
func (self SearchVersionRecordsSource) Open() (SearchVersionInput, error) {
	slices.SortStableFunc(self, func(a SearchVersionRecord, b SearchVersionRecord) int {
		return compareSearchVersionRecords(&a, &b)
	})
	return &searchVersionListInput{records: self}, nil
}

// A sorted list being read, its records of one key folded.
type searchVersionListInput struct {
	records []SearchVersionRecord
	next    int
}

// The next key's record, the one superseding the rest of that key. See SearchVersionInput.
func (self *searchVersionListInput) Next() (SearchVersionRecord, bool, error) {
	if len(self.records) <= self.next {
		return SearchVersionRecord{}, false, nil
	}
	record := self.records[self.next]
	self.next += 1
	for self.next < len(self.records) && compareSearchVersionRecords(&self.records[self.next], &record) == 0 {
		if searchVersionSupersedes(&self.records[self.next], &record) {
			record = self.records[self.next]
		}
		self.next += 1
	}
	return record, true, nil
}

// Nothing past its cursor: the list is the caller's.
func (self *searchVersionListInput) ByteCount() int64 {
	return 0
}

// Holds nothing to close. See SearchVersionInput.
func (self *searchVersionListInput) Close() {}

// The records of an index slot, head or large entry's entries (§11.14's entry row), sorted in memory, since a slot's
// order mixes doc keys and ref ids: a full entry or a diff is a version of its document, a tombstone deletes it, and a
// ref tombstone deletes every row of its ref at or below its version. file is the file they came from.
func searchVersionEntriesSource(entries []*indexEntry, file SearchVersionFile) SearchVersionRecordsSource {
	records := make([]SearchVersionRecord, 0, len(entries))
	for _, entry := range entries {
		record := SearchVersionRecord{Key: entry.key, Version: entry.version, File: file}
		switch entry.kind {
		case indexEntryTombstone:
			record.Tombstone = true
		case indexEntryRefTombstone:
			record.RefTombstone = true
		}
		records = append(records, record)
	}
	return SearchVersionRecordsSource(records)
}

// A shard's doc table and tombstones (§11.14's doc table and tombstones rows) as one key-ordered input, read by frame
// through reader: its documents, ascending by doc_key as their docids do, and its kind 3 tombstones interleaved by key,
// then its ref tombstones. file is the shard's path and entry version.
type searchVersionShardSource struct {
	reader *indexShardReader
	file   SearchVersionFile
}

// Reads the shard's tombstone table and starts at its first document. See SearchVersionSource.
func (self *searchVersionShardSource) Open() (SearchVersionInput, error) {
	input := &searchVersionShardInput{reader: self.reader, file: self.file}
	if err := input.readTombstones(); err != nil {
		return nil, err
	}
	return input, nil
}

// A shard being read: the next document's docid, and its tombstones, read once, in table order.
type searchVersionShardInput struct {
	reader     *indexShardReader
	file       SearchVersionFile
	docId      uint32
	tombstones []*indexShardTombstone
	nextStone  int
	document   *SearchVersionRecord
}

// Reads the tombstone table, which a bucket keeps until its roll-up and an all shard holds none of.
func (self *searchVersionShardInput) readTombstones() error {
	layout := self.reader.layout
	position := layout.tombstonesStart
	for range layout.header.Tombstones {
		window, err := self.reader.window(position, layout.dictionaryStart, indexTombstoneMaxByteCount)
		if err != nil {
			return err
		}
		decoder := indexDecoder{src: window}
		tombstone := decoder.tombstone(self.reader.companion)
		if decoder.err != nil {
			return decoder.err
		}
		self.tombstones = append(self.tombstones, tombstone)
		position += len(window) - decoder.remaining()
	}
	return indexCheckTombstoneOrder(self.tombstones, self.reader.companion)
}

// The next of the shard's documents and tombstones in key order. See SearchVersionInput.
func (self *searchVersionShardInput) Next() (SearchVersionRecord, bool, error) {
	if self.document == nil && int(self.docId) < self.reader.documentCount() {
		document, err := self.reader.document(self.docId)
		if err != nil {
			return SearchVersionRecord{}, false, err
		}
		self.docId += 1
		self.document = &SearchVersionRecord{Key: document.key, Version: document.version, File: self.file}
	}
	var stone *SearchVersionRecord
	if self.nextStone < len(self.tombstones) {
		tombstone := self.tombstones[self.nextStone]
		stone = &SearchVersionRecord{Key: tombstone.key, Version: tombstone.version, File: self.file}
		if tombstone.kind == indexEntryRefTombstone {
			stone.RefTombstone = true
		} else {
			stone.Tombstone = true
		}
	}
	switch {
	case self.document == nil && stone == nil:
		return SearchVersionRecord{}, false, nil
	case stone == nil || (self.document != nil && compareSearchVersionRecords(self.document, stone) < 0):
		record := *self.document
		self.document = nil
		return record, true, nil
	}
	self.nextStone += 1
	return *stone, true, nil
}

// One frame and the tombstones.
func (self *searchVersionShardInput) ByteCount() int64 {
	return int64(EvsRecordFrameByteCount) + int64(len(self.tombstones))*int64(indexTombstoneMaxByteCount+16)
}

// Holds nothing to close: the reader is the caller's. See SearchVersionInput.
func (self *searchVersionShardInput) Close() {}
