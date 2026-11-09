// Reading a shard by frame (§11.14's plan and verify rows; §5.9's holds row). An index file is an evs record whose body
// is sealed in 64 KiB frames (§11.6), and a phone decrypts one frame at a time and holds no more, so a reader here
// works over a frame source through a cursor holding one frame. Opening a shard walks its doc table, tombstones and
// block index once, keeping each document's offset and n_d, the block index and where each part starts: the layout,
// which SearchCache.PutDerived keeps so a later search opens the shard without reading its tables again. A search
// then reads only the block holding a key and that key's list, which may span frames.
//
// Opening refuses what it reads that breaks the format; walk reads everything and refuses every departure from the
// one canonical encoding, in memory proportional to the shard's documents and tombstones, which is what verification
// runs before a file is kept (indexValidateFile). Not safe for concurrent use.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"slices"
	"sort"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// One index file's plaintext, a frame at a time: its evs record's frames, 64 KiB each but the last.
type indexFrameSource interface {
	// The plaintext's length, pad included.
	indexLength() int
	// Frame index's plaintext. A source that must write it somewhere writes it into dst, which holds a whole frame and
	// belongs to the one cursor asking, so each cursor holds its own frame and no more; a source holding the whole
	// file may return its own bytes instead.
	indexReadFrame(index int, dst []byte) ([]byte, error)
}

// A whole file in memory as a frame source.
type indexBytesFrames []byte

// The whole file's length.
func (self indexBytesFrames) indexLength() int {
	return len(self)
}

// A view of the file's own bytes, which never change, so dst goes unused.
func (self indexBytesFrames) indexReadFrame(index int, dst []byte) ([]byte, error) {
	start := index * EvsRecordFrameByteCount
	if index < 0 || len(self) <= start {
		return nil, indexMalformed("a frame past the file")
	}
	return self[start:min(len(self), start+EvsRecordFrameByteCount)], nil
}

// Reads a file's bytes at any position, a frame at a time, holding one frame in a buffer of its own.
type indexFrameCursor struct {
	source     indexFrameSource
	buffer     []byte
	frame      []byte
	frameIndex int
}

// A cursor holding no frame yet.
func indexNewFrameCursor(source indexFrameSource) *indexFrameCursor {
	return &indexFrameCursor{source: source, frameIndex: -1}
}

// Fills dst with the file's bytes from position, reading each frame it crosses in turn.
func (self *indexFrameCursor) read(position int, dst []byte) error {
	length := self.source.indexLength()
	if position < 0 || length-position < len(dst) {
		return indexMalformed("a read past the file")
	}
	for 0 < len(dst) {
		index := position / EvsRecordFrameByteCount
		if index != self.frameIndex {
			if self.buffer == nil {
				self.buffer = make([]byte, EvsRecordFrameByteCount)
			}
			self.frameIndex = -1
			frame, err := self.source.indexReadFrame(index, self.buffer)
			if err != nil {
				return err
			}
			// Each frame's length is fixed by the file's, and a short one would stall this loop.
			if len(frame) != min(EvsRecordFrameByteCount, length-index*EvsRecordFrameByteCount) {
				return indexMalformed("a frame of the wrong length")
			}
			self.frame = frame
			self.frameIndex = index
		}
		copied := copy(dst, self.frame[position-self.frameIndex*EvsRecordFrameByteCount:])
		dst = dst[copied:]
		position += copied
	}
	return nil
}

// Where a shard's parts sit, from the file's first byte, with its documents' offsets and n_d and its block index:
// what a reader learns by opening the shard, and all it needs to find any key's list or any document's row.
type indexShardLayout struct {
	header          *protocol.IndexFileHeader
	length          int
	docTableStart   int
	tombstonesStart int
	dictionaryStart int
	keyEntriesStart int
	postingsStart   int
	// Where the pad starts.
	bodyEnd int
	// By docid: where its doc table entry starts, and its row's trigram count, n_d.
	documentStarts []uint32
	trigramCounts  []uint32
	blocks         []indexDictionaryBlock
}

// Where a key's list is, and what it holds, as its key entry says.
type indexKeyLocation struct {
	key          indexDictionaryKey
	listPosition int
}

// Reads one shard by frame.
type indexShardReader struct {
	companion bool
	cursor    *indexFrameCursor
	layout    *indexShardLayout
	scratch   []byte
}

// Up to maxByteCount bytes from position, stopping at end, copied out of the frames they sit in, for a decoder that
// stops where its entry does.
func (self *indexShardReader) window(position int, end int, maxByteCount int) ([]byte, error) {
	byteCount := min(maxByteCount, end-position)
	if byteCount < 0 {
		return nil, indexMalformed("a read past its part")
	}
	if cap(self.scratch) < byteCount {
		self.scratch = make([]byte, byteCount)
	}
	window := self.scratch[:byteCount]
	if err := self.cursor.read(position, window); err != nil {
		return nil, err
	}
	return window, nil
}

// Opens a shard: its header, then its doc table, tombstones and block index read once, and the last block's entries,
// which fix where the postings start. companion says whether it sits under ur/index's root. A file in a newer format
// answers errIndexNewerFormat.
func indexOpenShard(source indexFrameSource, companion bool) (*indexShardReader, error) {
	reader := &indexShardReader{companion: companion, cursor: indexNewFrameCursor(source)}
	layout := &indexShardLayout{length: source.indexLength()}
	if indexShardPaddedMaxByteCount < layout.length {
		return nil, indexMalformed("a file past 1 MiB")
	}

	prefix, err := reader.window(0, layout.length, len(indexFileMagic)+indexVByteMaxByteCount)
	if err != nil {
		return nil, err
	}
	prefixDecoder := indexDecoder{src: bytes.Clone(prefix)}
	prefixDecoder.take(uint64(len(indexFileMagic)))
	headerByteCount := prefixDecoder.vbyte()
	if prefixDecoder.err != nil {
		return nil, prefixDecoder.err
	}
	headerStart := len(prefix) - prefixDecoder.remaining()
	if uint64(layout.length-headerStart) < headerByteCount {
		return nil, indexMalformed("a header past the end of its input")
	}
	headerEnd := headerStart + int(headerByteCount)
	headerBytes := make([]byte, headerEnd)
	if err := reader.cursor.read(0, headerBytes); err != nil {
		return nil, err
	}
	headerDecoder := indexDecoder{src: headerBytes}
	layout.header = headerDecoder.fileHeader()
	if headerDecoder.err != nil {
		return nil, headerDecoder.err
	}
	if err := indexCheckShardHeader(layout.header); err != nil {
		return nil, err
	}
	if uint64(layout.length-headerEnd) < uint64(layout.header.BodyLength) {
		return nil, indexMalformed("a body past the end of its input")
	}
	layout.bodyEnd = headerEnd + int(layout.header.BodyLength)
	if indexShardMaxByteCount < layout.bodyEnd {
		return nil, indexMalformed("a shard past its cap before its pad")
	}

	position := headerEnd
	layout.docTableStart = position
	documentCount := int(layout.header.Count)
	if (layout.bodyEnd-position)/indexDocumentEntryMinByteCount < documentCount {
		return nil, indexMalformed("a document count past the end of its input")
	}
	layout.documentStarts = make([]uint32, 0, documentCount)
	layout.trigramCounts = make([]uint32, 0, documentCount)
	var previousKey [indexIdByteCount]byte
	for docId := range documentCount {
		window, err := reader.window(position, layout.bodyEnd, indexDocumentEntryMaxByteCount)
		if err != nil {
			return nil, err
		}
		decoder := indexDecoder{src: window}
		document := decoder.shardDocument(companion)
		if decoder.err != nil {
			return nil, decoder.err
		}
		if 0 < docId && bytes.Compare(previousKey[:], document.key[:]) >= 0 {
			return nil, indexMalformed("documents out of order or repeated")
		}
		if indexKeyMax+1 < document.row.trigramCount {
			return nil, indexMalformed("a trigram count past every key")
		}
		previousKey = document.key
		layout.documentStarts = append(layout.documentStarts, uint32(position))
		layout.trigramCounts = append(layout.trigramCounts, uint32(document.row.trigramCount))
		position += len(window) - decoder.remaining()
	}

	layout.tombstonesStart = position
	tombstoneCount := int(layout.header.Tombstones)
	if (layout.bodyEnd-position)/(indexTombstoneFixedByteCount+2) < tombstoneCount {
		return nil, indexMalformed("a tombstone count past the end of its input")
	}
	var previous *indexShardTombstone
	for range tombstoneCount {
		window, err := reader.window(position, layout.bodyEnd, indexTombstoneMaxByteCount)
		if err != nil {
			return nil, err
		}
		decoder := indexDecoder{src: window}
		tombstone := decoder.tombstone(companion)
		if decoder.err != nil {
			return nil, decoder.err
		}
		if previous != nil && 0 <= indexCompareTombstones(previous, tombstone) {
			return nil, indexMalformed("tombstones out of order or repeated")
		}
		previous = tombstone
		position += len(window) - decoder.remaining()
	}

	layout.dictionaryStart = position
	window, err := reader.window(position, layout.bodyEnd, indexVByteMaxByteCount)
	if err != nil {
		return nil, err
	}
	countDecoder := indexDecoder{src: window}
	blockCount := countDecoder.vbyte()
	if countDecoder.err != nil {
		return nil, countDecoder.err
	}
	position += len(window) - countDecoder.remaining()
	if uint64((layout.bodyEnd-position)/(indexTrigramByteCount+2)) < blockCount {
		return nil, indexMalformed("a block count past the end of its input")
	}
	layout.blocks = make([]indexDictionaryBlock, 0, blockCount)
	for index := range int(blockCount) {
		window, err := reader.window(position, layout.bodyEnd, indexBlockEntryMaxByteCount)
		if err != nil {
			return nil, err
		}
		decoder := indexDecoder{src: window}
		block := decoder.dictionaryBlock()
		if decoder.err != nil {
			return nil, decoder.err
		}
		if index == 0 && (block.entriesOffset != 0 || block.listOffset != 0) {
			return nil, indexMalformed("a first block whose offsets are not zero")
		}
		if 0 < index {
			last := layout.blocks[index-1]
			if block.firstKey <= last.firstKey || block.entriesOffset <= last.entriesOffset || block.listOffset <= last.listOffset {
				return nil, indexMalformed("a block index out of order")
			}
		}
		layout.blocks = append(layout.blocks, block)
		position += len(window) - decoder.remaining()
	}
	layout.keyEntriesStart = position

	if blockCount == 0 {
		if position != layout.bodyEnd {
			return nil, indexMalformed("postings with no dictionary")
		}
		layout.postingsStart = position
	} else {
		if documentCount == 0 {
			return nil, indexMalformed("a key in a shard of no documents")
		}
		// The last block's entries end where the postings start, and the postings end where the body does, at the
		// last block's list offset plus its lists. That sum grows with every entry read, so one entry count meets it.
		last := layout.blocks[blockCount-1]
		if uint64(layout.bodyEnd-layout.keyEntriesStart) <= last.entriesOffset {
			return nil, indexMalformed("a block past the end of its input")
		}
		position = layout.keyEntriesStart + int(last.entriesOffset)
		listByteCount := last.listOffset
		previous := uint32(0)
		for count := 0; ; count += 1 {
			if count == indexBlockMaxKeyCount {
				return nil, indexMalformed("a block of more than 64 keys")
			}
			window, err := reader.window(position, layout.bodyEnd, indexKeyEntryMaxByteCount)
			if err != nil {
				return nil, err
			}
			decoder := indexDecoder{src: window}
			entry := decoder.keyEntry(previous, count == 0)
			if decoder.err != nil {
				return nil, decoder.err
			}
			if count == 0 && entry.key != last.firstKey {
				return nil, indexMalformed("a block's first key that is not its index's")
			}
			previous = entry.key
			position += len(window) - decoder.remaining()
			listByteCount += entry.listByteCount
			if uint64(layout.bodyEnd-position) == listByteCount {
				break
			}
			if uint64(layout.bodyEnd-position) < listByteCount {
				return nil, indexMalformed("lists past the end of the body")
			}
		}
		layout.postingsStart = position
	}
	reader.layout = layout
	return reader, nil
}

// The number of live documents, N.
func (self *indexShardReader) documentCount() int {
	return len(self.layout.trigramCounts)
}

// A document's doc table entry by docid, without its keys.
func (self *indexShardReader) document(docId uint32) (*indexShardDocument, error) {
	if int(docId) >= len(self.layout.documentStarts) {
		return nil, indexMalformed("a docid out of range")
	}
	window, err := self.window(int(self.layout.documentStarts[docId]), self.layout.tombstonesStart, indexDocumentEntryMaxByteCount)
	if err != nil {
		return nil, err
	}
	decoder := indexDecoder{src: window}
	document := decoder.shardDocument(self.companion)
	if decoder.err != nil {
		return nil, decoder.err
	}
	return document, nil
}

// Where key's list is, or false when the shard holds no such key. Only the block that could hold it is read.
func (self *indexShardReader) lookup(key uint32) (indexKeyLocation, bool, error) {
	blocks := self.layout.blocks
	blockIndex := sort.Search(len(blocks), func(index int) bool {
		return key < blocks[index].firstKey
	}) - 1
	if blockIndex < 0 {
		return indexKeyLocation{}, false, nil
	}
	block := blocks[blockIndex]
	position := self.layout.keyEntriesStart + int(block.entriesOffset)
	end := self.layout.postingsStart
	if blockIndex+1 < len(blocks) {
		end = self.layout.keyEntriesStart + int(blocks[blockIndex+1].entriesOffset)
	}
	listPosition := self.layout.postingsStart + int(block.listOffset)
	previous := uint32(0)
	for count := 0; position < end; count += 1 {
		if count == indexBlockMaxKeyCount {
			return indexKeyLocation{}, false, indexMalformed("a block of more than 64 keys")
		}
		window, err := self.window(position, end, indexKeyEntryMaxByteCount)
		if err != nil {
			return indexKeyLocation{}, false, err
		}
		decoder := indexDecoder{src: window}
		entry := decoder.keyEntry(previous, count == 0)
		if decoder.err != nil {
			return indexKeyLocation{}, false, decoder.err
		}
		if count == 0 && entry.key != block.firstKey {
			return indexKeyLocation{}, false, indexMalformed("a block's first key that is not its index's")
		}
		if entry.key == key {
			return indexKeyLocation{key: entry, listPosition: listPosition}, true, nil
		}
		if key < entry.key {
			break
		}
		position += len(window) - decoder.remaining()
		listPosition += int(entry.listByteCount)
		previous = entry.key
	}
	return indexKeyLocation{}, false, nil
}

// The list at location, read across whatever frames it spans into memory of its own: never more than the shard's
// bitset, a few KiB.
func (self *indexShardReader) list(location indexKeyLocation) (*indexPostingList, error) {
	documentCount := self.documentCount()
	byteCount := location.key.listByteCount
	if uint64(indexBitsetByteCount(documentCount)) < byteCount {
		return nil, indexMalformed("a list longer than its shard's bitset")
	}
	if location.listPosition < self.layout.postingsStart || uint64(self.layout.bodyEnd-location.listPosition) < byteCount {
		return nil, indexMalformed("a list past the postings")
	}
	encoded := make([]byte, byteCount)
	if err := self.cursor.read(location.listPosition, encoded); err != nil {
		return nil, err
	}
	return indexDecodeList(encoded, location.key.bitset, location.key.documentCount, documentCount)
}

// What walk hands on, each optional: every document in docid order, every tombstone in table order, and every key
// with its list in key order, with the block it sits in.
type indexShardVisitor struct {
	document  func(docId uint32, document *indexShardDocument) error
	tombstone func(tombstone *indexShardTombstone) error
	key       func(blockIndex int, key indexDictionaryKey, list *indexPostingList) error
}

// Reads the whole shard, refusing every departure from its canonical encoding that opening did not: a pad byte that is
// not zero, a tombstone table naming a key twice or a key its doc table holds, a part that does not end where the next
// begins, a dictionary out of order or its offsets off, a block of no keys or more than 64, a list off the
// shorter-list rule or naming a docid out of range, and a row whose trigram count is not the lists holding it. Memory
// is the tombstones' keys, a count a document and a second cursor for the postings.
func (self *indexShardReader) walk(visitor indexShardVisitor) error {
	layout := self.layout
	for position := layout.bodyEnd; position < layout.length; {
		window, err := self.window(position, layout.length, EvsRecordFrameByteCount)
		if err != nil {
			return err
		}
		for _, b := range window {
			if b != 0 {
				return indexMalformed("a pad byte that is not zero")
			}
		}
		position += len(window)
	}

	tombstones := make([]*indexShardTombstone, 0, layout.header.Tombstones)
	position := layout.tombstonesStart
	for range layout.header.Tombstones {
		window, err := self.window(position, layout.dictionaryStart, indexTombstoneMaxByteCount)
		if err != nil {
			return err
		}
		decoder := indexDecoder{src: window}
		tombstone := decoder.tombstone(self.companion)
		if decoder.err != nil {
			return decoder.err
		}
		tombstones = append(tombstones, tombstone)
		position += len(window) - decoder.remaining()
	}
	if position != layout.dictionaryStart {
		return indexMalformed("a tombstone table that does not end at the dictionary")
	}
	if err := indexCheckTombstoneOrder(tombstones, self.companion); err != nil {
		return err
	}
	tombstoneKeys := make([][indexIdByteCount]byte, 0, len(tombstones))
	for _, tombstone := range tombstones {
		if visitor.tombstone != nil {
			if err := visitor.tombstone(tombstone); err != nil {
				return err
			}
		}
		tombstoneKeys = append(tombstoneKeys, tombstone.key)
	}
	slices.SortFunc(tombstoneKeys, func(a [indexIdByteCount]byte, b [indexIdByteCount]byte) int {
		return bytes.Compare(a[:], b[:])
	})

	documentCount := self.documentCount()
	position = layout.docTableStart
	keyIndex := 0
	var previousKey [indexIdByteCount]byte
	for docId := range documentCount {
		if int(layout.documentStarts[docId]) != position {
			return indexMalformed("a document that does not start where the last ended")
		}
		window, err := self.window(position, layout.tombstonesStart, indexDocumentEntryMaxByteCount)
		if err != nil {
			return err
		}
		decoder := indexDecoder{src: window}
		document := decoder.shardDocument(self.companion)
		if decoder.err != nil {
			return decoder.err
		}
		if 0 < docId && bytes.Compare(previousKey[:], document.key[:]) >= 0 {
			return indexMalformed("documents out of order or repeated")
		}
		if uint64(layout.trigramCounts[docId]) != document.row.trigramCount {
			return indexMalformed("a trigram count that is not its layout's")
		}
		for keyIndex < len(tombstoneKeys) && bytes.Compare(tombstoneKeys[keyIndex][:], document.key[:]) < 0 {
			keyIndex += 1
		}
		if keyIndex < len(tombstoneKeys) && tombstoneKeys[keyIndex] == document.key {
			return indexMalformed("a key in both of a shard's tables")
		}
		previousKey = document.key
		if visitor.document != nil {
			if err := visitor.document(uint32(docId), document); err != nil {
				return err
			}
		}
		position += len(window) - decoder.remaining()
	}
	if position != layout.tombstonesStart {
		return indexMalformed("a doc table that does not end at its tombstones")
	}

	keyCounts := make([]uint32, documentCount)
	listCursor := indexNewFrameCursor(self.cursor.source)
	listPosition := layout.postingsStart
	position = layout.keyEntriesStart
	lastKey := -1
	for blockIndex, block := range layout.blocks {
		if position != layout.keyEntriesStart+int(block.entriesOffset) {
			return indexMalformed("a block's entries offset off")
		}
		if listPosition != layout.postingsStart+int(block.listOffset) {
			return indexMalformed("a block's list offset off")
		}
		end := layout.postingsStart
		if blockIndex+1 < len(layout.blocks) {
			end = layout.keyEntriesStart + int(layout.blocks[blockIndex+1].entriesOffset)
		}
		previous := uint32(0)
		for count := 0; count == 0 || position < end; count += 1 {
			if count == indexBlockMaxKeyCount {
				return indexMalformed("a block of more than 64 keys")
			}
			window, err := self.window(position, end, indexKeyEntryMaxByteCount)
			if err != nil {
				return err
			}
			decoder := indexDecoder{src: window}
			entry := decoder.keyEntry(previous, count == 0)
			if decoder.err != nil {
				return decoder.err
			}
			if count == 0 && (entry.key != block.firstKey || int(entry.key) <= lastKey) {
				return indexMalformed("a block's first key out of order")
			}
			position += len(window) - decoder.remaining()
			if uint64(indexBitsetByteCount(documentCount)) < entry.listByteCount {
				return indexMalformed("a list longer than its shard's bitset")
			}
			if uint64(layout.bodyEnd-listPosition) < entry.listByteCount {
				return indexMalformed("a list past the postings")
			}
			encoded := make([]byte, entry.listByteCount)
			if err := listCursor.read(listPosition, encoded); err != nil {
				return err
			}
			list, err := indexDecodeList(encoded, entry.bitset, entry.documentCount, documentCount)
			if err != nil {
				return err
			}
			for _, docId := range list.all() {
				keyCounts[docId] += 1
			}
			if visitor.key != nil {
				if err := visitor.key(blockIndex, entry, list); err != nil {
					return err
				}
			}
			listPosition += int(entry.listByteCount)
			previous = entry.key
			lastKey = int(entry.key)
		}
		if position != end {
			return indexMalformed("a block that does not end where the next begins")
		}
	}
	if position != layout.postingsStart || listPosition != layout.bodyEnd {
		return indexMalformed("a dictionary that does not end at its postings")
	}
	for docId, count := range keyCounts {
		if count != layout.trigramCounts[docId] {
			return indexMalformed("a trigram count that is not its lists'")
		}
	}
	return nil
}

// Reads a whole shard into memory: its documents with their key sets inverted back from the postings, its tombstones,
// its block partition and its pad, for a writer, a merge, a roll-up or a rewrite. The hash comes first, so tampered
// bytes reach no parser, and what decodes must re-encode to the bytes it came from (FI-22).
func indexDecodeShard(file []byte, contentSha256 []byte, companion bool) (*indexShard, error) {
	sum := sha256.Sum256(file)
	if !bytes.Equal(sum[:], contentSha256) {
		return nil, indexMalformed("plaintext hash mismatch")
	}
	reader, err := indexOpenShard(indexBytesFrames(file), companion)
	if err != nil {
		return nil, err
	}
	shard := &indexShard{
		header:       reader.layout.header,
		documents:    make([]*indexShardDocument, 0, reader.documentCount()),
		tombstones:   []*indexShardTombstone{},
		padByteCount: reader.layout.length - reader.layout.bodyEnd,
	}
	blockKeyCounts := make([]int, len(reader.layout.blocks))
	err = reader.walk(indexShardVisitor{
		document: func(docId uint32, document *indexShardDocument) error {
			// Sized by the lists as they come, never by a row's count before walk has checked it.
			document.keys = indexKeySet{}
			shard.documents = append(shard.documents, document)
			return nil
		},
		tombstone: func(tombstone *indexShardTombstone) error {
			shard.tombstones = append(shard.tombstones, tombstone)
			return nil
		},
		key: func(blockIndex int, key indexDictionaryKey, list *indexPostingList) error {
			blockKeyCounts[blockIndex] += 1
			for _, docId := range list.all() {
				shard.documents[docId].keys = append(shard.documents[docId].keys, key.key)
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	shard.blockKeyCounts = blockKeyCounts
	again, err := indexNewShardBuilder(companion).encode(shard)
	if err != nil || !bytes.Equal(again, file) {
		return nil, indexMalformed("a shard that does not re-encode to its bytes")
	}
	return shard, nil
}

// The layout as derived data for SearchCache.PutDerived (§5.9's holds row): the header's bytes, the part offsets, each
// document's start and n_d, and the block index, all VByte, starts and first keys as gaps. It is this device's own,
// sealed under its local search key, and never leaves it.
func (self *indexShardLayout) appendEncoded(dst []byte) ([]byte, error) {
	header, err := indexMarshalHeader(self.header)
	if err != nil {
		return nil, err
	}
	dst = indexAppendVByte(dst, uint64(len(header)))
	dst = append(dst, header...)
	for _, position := range []int{self.length, self.docTableStart, self.tombstonesStart, self.dictionaryStart, self.keyEntriesStart, self.postingsStart, self.bodyEnd} {
		dst = indexAppendVByte(dst, uint64(position))
	}
	dst = indexAppendVByte(dst, uint64(len(self.documentStarts)))
	last := uint32(0)
	for docId, start := range self.documentStarts {
		dst = indexAppendVByte(dst, uint64(start-last))
		dst = indexAppendVByte(dst, uint64(self.trigramCounts[docId]))
		last = start
	}
	dst = indexAppendVByte(dst, uint64(len(self.blocks)))
	lastKey := uint32(0)
	for _, block := range self.blocks {
		dst = indexAppendVByte(dst, uint64(block.firstKey-lastKey))
		dst = indexAppendVByte(dst, block.entriesOffset)
		dst = indexAppendVByte(dst, block.listOffset)
		lastKey = block.firstKey
	}
	return dst, nil
}

// Reads a layout appendEncoded wrote, refusing one whose parts are out of order or past the file, so a reader opened
// on it reads only inside the file.
func indexDecodeShardLayout(encoded []byte) (*indexShardLayout, error) {
	decoder := indexDecoder{src: encoded}
	headerBytes := decoder.take(decoder.vbyte())
	if decoder.err != nil {
		return nil, decoder.err
	}
	layout := &indexShardLayout{header: &protocol.IndexFileHeader{}}
	if err := proto.Unmarshal(headerBytes, layout.header); err != nil {
		return nil, indexMalformed("a layout's header that does not parse")
	}
	if err := indexCheckShardHeader(layout.header); err != nil {
		return nil, err
	}
	positions := []*int{&layout.length, &layout.docTableStart, &layout.tombstonesStart, &layout.dictionaryStart, &layout.keyEntriesStart, &layout.postingsStart, &layout.bodyEnd}
	for _, position := range positions {
		value := decoder.vbyte()
		if indexShardPaddedMaxByteCount < value {
			decoder.refuse("a layout position past 1 MiB")
		}
		*position = int(value)
	}
	if decoder.err != nil {
		return nil, decoder.err
	}
	if !(layout.docTableStart <= layout.tombstonesStart && layout.tombstonesStart <= layout.dictionaryStart &&
		layout.dictionaryStart <= layout.keyEntriesStart && layout.keyEntriesStart <= layout.postingsStart &&
		layout.postingsStart <= layout.bodyEnd && layout.bodyEnd <= layout.length) {
		return nil, indexMalformed("a layout's parts out of order")
	}
	documentCount := decoder.vbyte()
	if uint64(decoder.remaining()/2) < documentCount || uint64(layout.header.Count) != documentCount {
		decoder.refuse("a layout's document count off")
	}
	if decoder.err != nil {
		return nil, decoder.err
	}
	layout.documentStarts = make([]uint32, 0, documentCount)
	layout.trigramCounts = make([]uint32, 0, documentCount)
	start := uint64(0)
	for docId := range documentCount {
		gap := decoder.vbyte()
		trigramCount := decoder.vbyte()
		start += gap
		if (0 < docId && gap == 0) || start < uint64(layout.docTableStart) || uint64(layout.tombstonesStart) <= start || indexKeyMax+1 < trigramCount {
			decoder.refuse("a layout's document out of place")
		}
		if decoder.err != nil {
			return nil, decoder.err
		}
		layout.documentStarts = append(layout.documentStarts, uint32(start))
		layout.trigramCounts = append(layout.trigramCounts, uint32(trigramCount))
	}
	blockCount := decoder.vbyte()
	if uint64(decoder.remaining()/3) < blockCount {
		decoder.refuse("a layout's block count off")
	}
	if decoder.err != nil {
		return nil, decoder.err
	}
	layout.blocks = make([]indexDictionaryBlock, 0, blockCount)
	firstKey := uint64(0)
	for index := range blockCount {
		gap := decoder.vbyte()
		block := indexDictionaryBlock{entriesOffset: decoder.vbyte(), listOffset: decoder.vbyte()}
		firstKey += gap
		if (0 < index && gap == 0) || indexKeyMax < firstKey ||
			uint64(layout.postingsStart-layout.keyEntriesStart) <= block.entriesOffset ||
			uint64(layout.bodyEnd-layout.postingsStart) <= block.listOffset {
			decoder.refuse("a layout's block out of place")
		}
		if decoder.err != nil {
			return nil, decoder.err
		}
		block.firstKey = uint32(firstKey)
		layout.blocks = append(layout.blocks, block)
	}
	if decoder.remaining() != 0 {
		return nil, indexMalformed("bytes past a layout")
	}
	return layout, nil
}

// A reader over source from a layout kept before, reading none of the shard's tables again. The layout must be the
// file's: its length is checked here, and its hash was when the file was kept.
func indexOpenShardWithLayout(source indexFrameSource, companion bool, layout *indexShardLayout) (*indexShardReader, error) {
	if source.indexLength() != layout.length {
		return nil, indexMalformed("a layout of another file")
	}
	return &indexShardReader{companion: companion, cursor: indexNewFrameCursor(source), layout: layout}, nil
}
