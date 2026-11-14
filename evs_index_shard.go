// Shards (§11.14's shard, doc table, shrink and caps rows; protocol/INDEX-FORMAT.md's Shards): a bucket's merged
// entries, or the all partition's, as one file of at most 1,032,192 B before its pad and 1 MiB with it, so every
// index file is one ?closure=1 upload:
//
//	"URix" | VByte header length | IndexFileHeader | doc table | tombstones | dictionary | postings | pad
//
// A docid is a live document's rank by doc_key. Rows are copied from their entries and never refer to one another;
// the dictionary and lists are the only structures shared across documents, so they sit under the keyed pad and
// nothing is compressed across documents (§11.14's codes row). A shard is a function of its documents, tombstones and
// block partition, so two devices that build one from the same inputs write the same plaintext (FI-22).
//
// Writers, merges, roll-ups and rewrites build here; readers read through indexShardReader, by frame.

package sidecar

import (
	"bytes"
	"container/heap"
	"errors"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.14's caps: a shard before its pad, and any index file with it. Padmé's step at the first is 16 KiB, so the
// keyed pad of a full shard reaches the second and never passes it.
const (
	indexShardMaxByteCount       = 1032192
	indexShardPaddedMaxByteCount = 1024 * 1024
)

// The shortest doc table entry: a doc_key, two one-byte VBytes and the shortest row, a doc kind, six VBytes and five
// empty texts. A count is checked against it before it sizes anything.
const indexDocumentEntryMinByteCount = indexIdByteCount + 2 + 1 + 6 + 5

// The longest doc table entry: a doc_key, two VBytes and the longest row.
const indexDocumentEntryMaxByteCount = indexIdByteCount + 2*indexVByteMaxByteCount + indexRowMaxByteCount

// A builder whose documents would pass a shard's cap, so it is no malformation. In a layout's take, its step 1 test and
// its step 3 test it is a test's answer, "does not encode within", and the layout goes on: take opens the next shard,
// a shard a removal lengthened gives up its highest entries, and a join is not made (§11.14's merges output row;
// DESIGN-DETAILS 1.2.4; QD-775). From a layout's last encode, or any other caller, it fails what it was building, a
// guard that QD-760's skip at extraction and QD-775's two tests leave no input a decoder accepts to reach.
var errIndexShardFull = errors.New("index shard past its cap")

// One live document of a shard: its doc table row and its key set, which the postings hold inverted.
type indexShardDocument struct {
	key         [indexIdByteCount]byte
	version     uint64
	timeSeconds uint64
	row         *indexRow
	keys        indexKeySet
}

// A shard decoded or being built. The encoder sets the header's count, tombstones and body_length.
type indexShard struct {
	header *protocol.IndexFileHeader
	// By doc_key, whatever order they are given in: their order is their docids.
	documents []*indexShardDocument
	// By kind, then key, whatever order they are given in.
	tombstones []*indexShardTombstone
	// The keys in each dictionary block. Nil blocks by 64, as every fresh shard does; a decoded shard keeps its own,
	// and a rewrite that could not fit by 64 keeps the replaced shard's (plan-SEARCH-shrink-claim).
	blockKeyCounts []int
	// Zero bytes after the body: the keyed pad, or a rewrite's padding to its replaced length.
	padByteCount int
}

// Refuses what a shard's header may not hold, for encoder and decoder alike. A shard names its tables and its pad's
// generation; a bucket shard its bucket, an all shard none and no tombstone; neither a writer, a seq or coverage,
// which are a head's.
func indexCheckShardHeader(header *protocol.IndexFileHeader) error {
	if header.Format != indexFormatVersion {
		return indexMalformed("a header with no format")
	}
	if header.Normalizer == 0 || header.Extractor == 0 || header.UnicodeVersion == "" || header.TextModuleVersion == "" {
		return indexMalformed("a header without its tables")
	}
	switch header.Type {
	case indexFileBucketShard:
		if header.BucketDays == 0 {
			return indexMalformed("a bucket shard without its bucket")
		}
	case indexFileAllShard:
		if header.BucketStartDay != 0 || header.BucketDays != 0 {
			return indexMalformed("an all shard naming a bucket")
		}
		if header.Tombstones != 0 {
			return indexMalformed("a tombstone in an all shard")
		}
	default:
		return indexMalformed("not a shard")
	}
	if len(header.WriterSidecarId) != 0 || header.Seq != 0 || len(header.Coverage) != 0 {
		return indexMalformed("a head's fields on a shard")
	}
	if header.PadGeneration == 0 {
		return indexMalformed("a shard without its pad's generation")
	}
	return nil
}

// A min-heap of documents' next keys, by key and then docid, so popping it yields every posting in list order.
type indexPostingHeap []*indexPostingCursor

// One document's place in the walk over its key set.
type indexPostingCursor struct {
	docId uint32
	keys  indexKeySet
	next  int
}

// heap.Interface, over the cursors still holding keys.
func (self indexPostingHeap) Len() int {
	return len(self)
}

// By the cursors' next keys, then their docids.
func (self indexPostingHeap) Less(i int, j int) bool {
	a, b := self[i], self[j]
	if a.keys[a.next] != b.keys[b.next] {
		return a.keys[a.next] < b.keys[b.next]
	}
	return a.docId < b.docId
}

// heap.Interface.
func (self indexPostingHeap) Swap(i int, j int) {
	self[i], self[j] = self[j], self[i]
}

// heap.Interface.
func (self *indexPostingHeap) Push(x any) {
	*self = append(*self, x.(*indexPostingCursor))
}

// heap.Interface.
func (self *indexPostingHeap) Pop() any {
	old := *self
	last := old[len(old)-1]
	*self = old[:len(old)-1]
	return last
}

// The dictionary keys and postings of documents in docid order: each key's list in the shorter form, inverted from the
// documents' key sets by a merge that holds one cursor a document.
func indexInvertPostings(documents []*indexShardDocument) ([]indexDictionaryKey, []byte) {
	cursors := make(indexPostingHeap, 0, len(documents))
	for docId, document := range documents {
		if 0 < len(document.keys) {
			cursors = append(cursors, &indexPostingCursor{docId: uint32(docId), keys: document.keys})
		}
	}
	heap.Init(&cursors)
	keys := []indexDictionaryKey{}
	postings := []byte{}
	docIds := []uint32{}
	flush := func(key uint32) {
		start := len(postings)
		var bitset bool
		postings, bitset = indexAppendList(postings, docIds, len(documents))
		keys = append(keys, indexDictionaryKey{
			key:           key,
			documentCount: uint64(len(docIds)),
			listByteCount: uint64(len(postings) - start),
			bitset:        bitset,
		})
		docIds = docIds[:0]
	}
	current := uint32(0)
	for 0 < cursors.Len() {
		cursor := cursors[0]
		key := cursor.keys[cursor.next]
		if 0 < len(docIds) && key != current {
			flush(current)
		}
		current = key
		docIds = append(docIds, cursor.docId)
		cursor.next += 1
		if cursor.next == len(cursor.keys) {
			heap.Pop(&cursors)
		} else {
			heap.Fix(&cursors, 0)
		}
	}
	if 0 < len(docIds) {
		flush(current)
	}
	return keys, postings
}

// Appends one doc table entry.
func (self *indexShardDocument) appendEncoded(dst []byte, companion bool) ([]byte, error) {
	dst = append(dst, self.key[:]...)
	dst = indexAppendVByte(dst, self.version)
	dst = indexAppendVByte(dst, self.timeSeconds)
	return self.row.appendEncoded(dst, companion)
}

// Reads one doc table entry, without its keys, which the postings hold.
func (self *indexDecoder) shardDocument(companion bool) *indexShardDocument {
	document := &indexShardDocument{}
	copy(document.key[:], self.take(indexIdByteCount))
	document.version = self.vbyte()
	document.timeSeconds = self.vbyte()
	if self.err != nil {
		return nil
	}
	document.row = self.row(companion)
	if self.err != nil {
		return nil
	}
	return document
}

// Builds shards: the documents in doc_key order, their postings inverted, the dictionary blocked, the header filled.
// Holds no state between builds. Not safe for concurrent use.
type indexShardBuilder struct {
	// Whether the shard sits under ur/index's root, where rows carry their ref_id and ref tombstones may sit.
	companion bool
}

// A builder for shards under ur/index's root or a file-mode ref's.
func indexNewShardBuilder(companion bool) *indexShardBuilder {
	return &indexShardBuilder{companion: companion}
}

// The shard before its pad, header filled, and the dictionary keys its postings hold. Refuses what a shard may not
// hold, and answers errIndexShardFull past the cap.
func (self *indexShardBuilder) encodeUnpadded(shard *indexShard) ([]byte, []indexDictionaryKey, error) {
	documents := slices.Clone(shard.documents)
	slices.SortFunc(documents, func(a *indexShardDocument, b *indexShardDocument) int {
		return bytes.Compare(a.key[:], b.key[:])
	})
	tombstones := slices.Clone(shard.tombstones)
	slices.SortFunc(tombstones, indexCompareTombstones)

	body := []byte{}
	for index, document := range documents {
		if 0 < index && documents[index-1].key == document.key {
			return nil, nil, indexMalformed("a document twice in one shard")
		}
		if document.row == nil {
			return nil, nil, indexMalformed("a document with no row")
		}
		if err := document.keys.check(); err != nil {
			return nil, nil, err
		}
		if document.row.trigramCount != uint64(len(document.keys)) {
			return nil, nil, indexMalformed("a trigram count that is not its key set's")
		}
		var err error
		if body, err = document.appendEncoded(body, self.companion); err != nil {
			return nil, nil, err
		}
	}
	if shard.header.Type == indexFileAllShard && len(tombstones) != 0 {
		return nil, nil, indexMalformed("a tombstone in an all shard")
	}
	if indexTombstonesMeetDocuments(tombstones, documents) {
		return nil, nil, indexMalformed("a key in both of a shard's tables")
	}
	var err error
	if body, err = indexAppendTombstones(body, tombstones, self.companion); err != nil {
		return nil, nil, err
	}
	keys, postings := indexInvertPostings(documents)
	partition, err := indexBlockPartition(len(keys), shard.blockKeyCounts)
	if err != nil {
		return nil, nil, err
	}
	body = indexAppendDictionary(body, keys, partition)
	body = append(body, postings...)

	header := proto.CloneOf(shard.header)
	header.Count = uint32(len(documents))
	header.Tombstones = uint32(len(tombstones))
	header.BodyLength = uint32(len(body))
	if err := indexCheckShardHeader(header); err != nil {
		return nil, nil, err
	}
	encodedHeader, err := indexMarshalHeader(header)
	if err != nil {
		return nil, nil, err
	}
	file := []byte(indexFileMagic)
	file = indexAppendVByte(file, uint64(len(encodedHeader)))
	file = append(file, encodedHeader...)
	if indexShardMaxByteCount < len(file)+len(body) {
		return nil, nil, errIndexShardFull
	}
	return append(file, body...), keys, nil
}

// The shard as merges, roll-ups and builds write it: blocks of 64, its header naming padKey's generation, and the
// keyed pad. shard's own partition and pad are not read.
func (self *indexShardBuilder) build(shard *indexShard, padKey *indexPadKey) ([]byte, error) {
	if padKey == nil {
		return nil, indexMalformed("a shard without its pad key")
	}
	canonical := *shard
	canonical.header = proto.CloneOf(shard.header)
	canonical.header.PadGeneration = padKey.generation
	canonical.blockKeyCounts = nil
	file, _, err := self.encodeUnpadded(&canonical)
	if err != nil {
		return nil, err
	}
	return append(file, make([]byte, padKey.padByteCount(file))...), nil
}

// The shard as it stands, its partition and pad included: what re-encoding a decoded shard reproduces.
func (self *indexShardBuilder) encode(shard *indexShard) ([]byte, error) {
	file, _, err := self.encodeUnpadded(shard)
	if err != nil {
		return nil, err
	}
	if shard.padByteCount < 0 {
		return nil, indexMalformed("a negative pad")
	}
	if indexShardPaddedMaxByteCount < len(file)+shard.padByteCount {
		return nil, indexMalformed("a file past its cap")
	}
	return append(file, make([]byte, shard.padByteCount)...), nil
}

// Whether a rewrite takes a live document (kind indexEntryFull) or a tombstone out.
type indexShardDrop func(kind indexEntryKind, key [indexIdByteCount]byte, version uint64) bool

// The shard rewritten in place without what drop takes, padded with zeros to replacedByteCount, the replaced version's
// exact length: a CLOSURE's rewrite or a DROP's (plan-SEARCH-shrink-claim, as the owner decided it; a roll-up rewrites
// nothing in place since DESIGN-DETAILS 1.2.5). It first builds by blocks of 64; if that outgrows the replaced length,
// or passes the shard's cap, which a removal from a shard a merge's take filled can do through the re-blocking (the
// case QD-775 settles for a layout), it keeps the replaced partition, each block its surviving keys and an emptied
// block gone, which always fits, since a removed key saves at least 4 B and costs the next at most 2. It keeps the
// replaced header's pad_generation either way. Past the replaced length all the same, which only a shard that was never
// canonical could give, it fails closed: the file is not written, and nothing is padded short.
func (self *indexShardBuilder) rewriteWithout(shard *indexShard, drop indexShardDrop, replacedByteCount int) ([]byte, *indexShard, error) {
	rewritten := &indexShard{header: proto.CloneOf(shard.header)}
	for _, document := range shard.documents {
		if !drop(indexEntryFull, document.key, document.version) {
			rewritten.documents = append(rewritten.documents, document)
		}
	}
	for _, tombstone := range shard.tombstones {
		if !drop(tombstone.kind, tombstone.key, tombstone.version) {
			rewritten.tombstones = append(rewritten.tombstones, tombstone)
		}
	}
	file, survivingKeys, err := self.encodeUnpadded(rewritten)
	pastCap := errors.Is(err, errIndexShardFull)
	if err != nil && !pastCap {
		return nil, nil, err
	}
	if pastCap {
		// past the cap by 64, so past any replaced length: the keys that survive, which the encoder did not hand back
		survivingKeys, _ = indexInvertPostings(rewritten.documents)
	}
	if pastCap || replacedByteCount < len(file) {
		// The replaced partition, each block keeping the keys that survive. Both key lists ascend.
		_, replacedKeys, err := self.encodeUnpadded(shard)
		if err != nil {
			return nil, nil, err
		}
		replacedPartition, err := indexBlockPartition(len(replacedKeys), shard.blockKeyCounts)
		if err != nil {
			return nil, nil, err
		}
		partition := []int{}
		next := 0
		surviving := 0
		for _, count := range replacedPartition {
			kept := 0
			for _, key := range replacedKeys[next : next+count] {
				for surviving < len(survivingKeys) && survivingKeys[surviving].key < key.key {
					surviving += 1
				}
				if surviving < len(survivingKeys) && survivingKeys[surviving].key == key.key {
					kept += 1
				}
			}
			if 0 < kept {
				partition = append(partition, kept)
			}
			next += count
		}
		rewritten.blockKeyCounts = partition
		if file, _, err = self.encodeUnpadded(rewritten); err != nil {
			return nil, nil, err
		}
	}
	padded, err := indexPadToExactly(file, replacedByteCount)
	if err != nil {
		return nil, nil, err
	}
	rewritten.padByteCount = replacedByteCount - len(file)
	return padded, rewritten, nil
}

// Whether a tombstone names a key the doc table holds. Both are in key order within a kind.
func indexTombstonesMeetDocuments(tombstones []*indexShardTombstone, documents []*indexShardDocument) bool {
	keys := make([][indexIdByteCount]byte, 0, len(tombstones))
	for _, tombstone := range tombstones {
		keys = append(keys, tombstone.key)
	}
	slices.SortFunc(keys, func(a [indexIdByteCount]byte, b [indexIdByteCount]byte) int {
		return bytes.Compare(a[:], b[:])
	})
	keyIndex := 0
	for _, document := range documents {
		for keyIndex < len(keys) && bytes.Compare(keys[keyIndex][:], document.key[:]) < 0 {
			keyIndex += 1
		}
		if keyIndex < len(keys) && keys[keyIndex] == document.key {
			return true
		}
	}
	return false
}
