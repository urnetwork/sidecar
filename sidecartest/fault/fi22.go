// FI-22, determinism (§22.8; §11.14's codes and determinism rows; D-TEST-15; TEST-M10-02), and the oracle's own reading
// of index format 1, which FI-18's, FI-19's and FI-20's checks read the index through.
//
// The codec here is written from protocol/INDEX-FORMAT.md alone and shares no index code (D-TEST-14): the oracle reads
// every index file version a source holds with it, encodes again what it read, and holds the two equal. A writer whose
// bytes are not the canonical encoding of what they hold fails here whatever the writer's own decoder makes of them, and
// what the other checks read is what the bytes say, not what the index's code says. Its output is compared, never
// trusted: a file that does not encode again to its bytes is FI-22's violation, and the other checks fail closed on it
// rather than read it.
//
// FI-22 holds, for every committed index file version each source (fi_search.go) names:
//
//	canonical  it decodes by its path's kind and encodes again to its bytes: the magic, a header that marshals again
//	           deterministically with no field format 1 lacks, minimal VByte, entries and doc tables ascending with one
//	           entry a key, rows within their caps and kinds, key sets ascending with no zero gap, tombstones by kind
//	           then key, the dictionary in blocks with each key's longest shared prefix, each list in its shorter form,
//	           a bitset's spare bits zero, and nothing past body_length but zero bytes; a small file is the bare message,
//	           marshaled again deterministically, its repeated fields sorted strictly
//	hashed     where the source names a version's content_sha256, it is the plaintext's SHA-256, taken before
//	           encryption
//	blocked    a shard a writer, a merge or a roll-up writes is blocked by 64, which an encoding from the file's own
//	           partition cannot see; only a CLOSURE's or a DROP's rewrite keeps a replaced partition
//	keyed pad  where the source names its repo's keys (SearchIndexKeys), a fresh shard's pad is §11.14's keyed pad
//	           at its header's pad_generation, so its length is a function of its bytes and nothing drawn fresh; a
//	           rewrite in place pads to the replaced length instead
//
// A format above 1 is left unread, as search reads status update. Byte-equality on every build leg is D-TEST-15's
// vectors, which every leg's test.sh runs, not a check after a step.

package fault

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/bits"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

var _ = RegisterInvariant(22, func(ctx context.Context, oracle *Oracle) error {
	return checkFi22(ctx, oracle)
})

// Index format 1's identifiers (protocol/INDEX-FORMAT.md): the magic, the format and tables, the file types, the entry,
// tombstone and doc kinds, the key entry's flag bits, and the keyed pad's label.
const (
	oracleIndexMagic         = "URix"
	oracleIndexFormatVersion = 1
	oracleIndexNormalizer    = 1
	oracleIndexExtractor     = 1

	oracleIndexTypeSlot        = 1
	oracleIndexTypeLargeEntry  = 2
	oracleIndexTypeBucketShard = 3
	oracleIndexTypeAllShard    = 4

	oracleIndexEntryFull         = 1
	oracleIndexEntryTombstone    = 3
	oracleIndexEntryRefTombstone = 4

	oracleIndexDocFile    = 1
	oracleIndexDocMail    = 2
	oracleIndexDocRecord  = 3
	oracleIndexDocDerived = 4

	oracleIndexPrefixMask = 0x03
	oracleIndexBitsetFlag = 0x04

	oracleIndexPadLabel = "pad"
	oracleIndexFileMode = ".ur-index/"
	oracleIndexErasure  = "x"
)

// Index format 1's limits as the oracle reads them, each the format's value (protocol/INDEX-FORMAT.md). They are the
// format's, not the index code's: an index whose own settings drift from these fails here.
type OracleIndexFormatSettings struct {
	// A slot's whole file, and each entry in one.
	SlotFileMaxByteCount  int
	SlotEntryMaxByteCount int
	// A large entry's whole file, and any index file with its pad.
	PaddedFileMaxByteCount int
	// A shard before its pad.
	ShardMaxByteCount int
	// A row in all, its locator, fields 1-4 and fields 6-15.
	RowMaxByteCount             int
	LocatorMaxByteCount         int
	HeaderFieldMaxByteCount     int
	RegisteredFieldMaxByteCount int
	// An encoded key set.
	KeySetMaxByteCount int
	// The keys of a dictionary block, and how a fresh shard blocks.
	BlockKeyCount int
	// A writer's slots in a bucket.
	WriterSlotCount uint32
	// a/ holds shards below this as files; from it on, each directory holds AllDirectoryShardCount.
	AllFileShardCount      uint32
	AllDirectoryShardCount uint32
}

func DefaultOracleIndexFormatSettings() *OracleIndexFormatSettings {
	return &OracleIndexFormatSettings{
		SlotFileMaxByteCount:        16208,
		SlotEntryMaxByteCount:       8192,
		PaddedFileMaxByteCount:      1024 * 1024,
		ShardMaxByteCount:           1032192,
		RowMaxByteCount:             2048,
		LocatorMaxByteCount:         512,
		HeaderFieldMaxByteCount:     160,
		RegisteredFieldMaxByteCount: 256,
		KeySetMaxByteCount:          512 * 1024,
		BlockKeyCount:               64,
		WriterSlotCount:             16,
		AllFileShardCount:           3499,
		AllDirectoryShardCount:      1000,
	}
}

// What an index path names.
type oracleIndexPathKind int

const (
	oracleIndexPathSettings oracleIndexPathKind = iota + 1
	oracleIndexPathLock
	oracleIndexPathAllManifest
	oracleIndexPathAllShard
	oracleIndexPathBucketManifest
	oracleIndexPathBucketShard
	oracleIndexPathSlot
	oracleIndexPathLargeEntry
	oracleIndexPathErasureSet
)

func (self oracleIndexPathKind) String() string {
	switch self {
	case oracleIndexPathSettings:
		return "settings"
	case oracleIndexPathLock:
		return "lock"
	case oracleIndexPathAllManifest:
		return "all manifest"
	case oracleIndexPathAllShard:
		return "all shard"
	case oracleIndexPathBucketManifest:
		return "bucket manifest"
	case oracleIndexPathBucketShard:
		return "bucket shard"
	case oracleIndexPathSlot:
		return "slot"
	case oracleIndexPathLargeEntry:
		return "large entry"
	case oracleIndexPathErasureSet:
		return "erasure set"
	}
	return "unknown"
}

// One index path as the format lays them out.
type oracleIndexPath struct {
	kind oracleIndexPathKind
	// Under ur/index, where rows carry their ref_id; else under a file-mode ref's .ur-index/.
	companion bool
	// i<root>; 0 for the erasure set, which sits beside the roots.
	root      uint32
	bucket    uint32
	shard     uint32
	writer    [16]byte
	slotIndex uint32
	seq       uint32
}

// A decimal with no leading zero, within 32 bits.
func oracleIndexDecimal(text string) (uint32, bool) {
	if text == "" || (1 < len(text) && text[0] == '0') {
		return 0, false
	}
	for _, r := range text {
		if r < '0' || '9' < r {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(text, 10, 32)
	return uint32(value), err == nil
}

// The path's kind and numbers, or false for a path that is no index file of format 1's layout.
func oracleIndexParsePath(path string, settings *OracleIndexFormatSettings) (oracleIndexPath, bool) {
	parsed := oracleIndexPath{companion: true}
	rest := path
	if strings.HasPrefix(rest, oracleIndexFileMode) {
		parsed.companion = false
		rest = rest[len(oracleIndexFileMode):]
	}
	if rest == oracleIndexErasure {
		parsed.kind = oracleIndexPathErasureSet
		return parsed, true
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "i") {
		return parsed, false
	}
	root, ok := oracleIndexDecimal(parts[0][1:])
	if !ok || root == 0 {
		return parsed, false
	}
	parsed.root = root
	switch {
	case len(parts) == 2 && parts[1] == "settings":
		parsed.kind = oracleIndexPathSettings
	case len(parts) == 2 && parts[1] == "lock":
		parsed.kind = oracleIndexPathLock
	case len(parts) == 3 && parts[1] == "a" && parts[2] == "m":
		parsed.kind = oracleIndexPathAllManifest
	case len(parts) == 3 && parts[1] == "a":
		n, ok := oracleIndexDecimal(parts[2])
		if !ok || settings.AllFileShardCount <= n {
			return parsed, false
		}
		parsed.kind = oracleIndexPathAllShard
		parsed.shard = n
	case len(parts) == 4 && parts[1] == "a":
		k, kOk := oracleIndexDecimal(parts[2])
		n, nOk := oracleIndexDecimal(parts[3])
		if !kOk || !nOk || n < settings.AllFileShardCount || k != settings.AllFileShardCount+(n-settings.AllFileShardCount)/settings.AllDirectoryShardCount {
			return parsed, false
		}
		parsed.kind = oracleIndexPathAllShard
		parsed.shard = n
	case len(parts) == 4 && parts[1] == "b" && parts[3] == "m":
		day, ok := oracleIndexDecimal(parts[2])
		if !ok {
			return parsed, false
		}
		parsed.kind = oracleIndexPathBucketManifest
		parsed.bucket = day
	case len(parts) == 5 && parts[1] == "b" && parts[3] == "s":
		day, dayOk := oracleIndexDecimal(parts[2])
		n, nOk := oracleIndexDecimal(parts[4])
		if !dayOk || !nOk {
			return parsed, false
		}
		parsed.kind = oracleIndexPathBucketShard
		parsed.bucket = day
		parsed.shard = n
	case len(parts) == 7 && parts[1] == "b" && parts[3] == "w":
		day, ok := oracleIndexDecimal(parts[2])
		if !ok {
			return parsed, false
		}
		writer := parts[5]
		if len(writer) != 32 || strings.ToLower(writer) != writer || parts[4] != writer[:2] {
			return parsed, false
		}
		writerBytes, err := hex.DecodeString(writer)
		if err != nil {
			return parsed, false
		}
		parsed.bucket = day
		copy(parsed.writer[:], writerBytes)
		if seqText, ok := strings.CutPrefix(parts[6], "L"); ok {
			seq, ok := oracleIndexDecimal(seqText)
			if !ok {
				return parsed, false
			}
			parsed.kind = oracleIndexPathLargeEntry
			parsed.seq = seq
		} else {
			k, ok := oracleIndexDecimal(parts[6])
			if !ok || settings.WriterSlotCount <= k {
				return parsed, false
			}
			parsed.kind = oracleIndexPathSlot
			parsed.slotIndex = k
		}
	default:
		return parsed, false
	}
	return parsed, true
}

// A row (protocol/INDEX-FORMAT.md's Rows).
type oracleIndexRow struct {
	docKind  uint8
	flags    uint64
	size     uint64
	chunk    uint64
	trigrams uint64
	started  uint64
	expires  uint64
	// In ur/index only.
	refId   []byte
	locator string
	// By field number; 0 and 5 stay empty, and 6-15 hold something only on record and derived rows.
	fields [16]string
}

// A row's fields in the order they encode: 1-4, and 6-15 on record and derived rows.
func (self *oracleIndexRow) fieldNumbers() []int {
	if self.docKind == oracleIndexDocRecord || self.docKind == oracleIndexDocDerived {
		return []int{1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	}
	return []int{1, 2, 3, 4}
}

// An entry of a slot or large entry, or a shard's live document (kind full) or tombstone.
type oracleIndexEntry struct {
	kind    uint8
	key     [16]byte
	version uint64
	// Seconds of the signed time of the content push that made the version.
	timeSeconds uint64
	// Full entries and shard documents: the row and the whole key set.
	row  *oracleIndexRow
	keys []uint32
}

func (self *oracleIndexEntry) live() bool {
	return self.kind == oracleIndexEntryFull
}

// One index file as the oracle read it.
type oracleIndexFile struct {
	path oracleIndexPath
	// Left unread: a format above 1.
	newer bool
	// Slots, large entries and shards.
	header *protocol.IndexFileHeader
	// Slots and large entries, in key order.
	entries []*oracleIndexEntry
	// Shards: the doc table in docid order, and the tombstone table by kind then key.
	documents  []*oracleIndexEntry
	tombstones []*oracleIndexEntry
	// Shards: the keys of each dictionary block.
	blockKeyCounts []int
	// Zero bytes after the body.
	padByteCount int
	// Small files.
	settingsFile *protocol.IndexSettings
	lock         *protocol.IndexLock
	manifest     *protocol.IndexManifest
	erasureSet   *protocol.IndexErasureSet
}

// Every entry the file holds with a key: a slot's or large entry's entries, a shard's documents and tombstones.
func (self *oracleIndexFile) keyedEntries() []*oracleIndexEntry {
	switch self.path.kind {
	case oracleIndexPathSlot, oracleIndexPathLargeEntry:
		return self.entries
	case oracleIndexPathBucketShard, oracleIndexPathAllShard:
		return append(slices.Clone(self.documents), self.tombstones...)
	}
	return nil
}

// --- reading ---

// A reader over one file's bytes, which stops at its first refusal.
type oracleIndexReader struct {
	src []byte
	at  int
	err error
}

func (self *oracleIndexReader) refuse(format string, a ...any) {
	if self.err == nil {
		self.err = fmt.Errorf("index file %s", fmt.Sprintf(format, a...))
	}
}

func (self *oracleIndexReader) remaining() int {
	return len(self.src) - self.at
}

func (self *oracleIndexReader) take(n uint64) []byte {
	if self.err != nil {
		return nil
	}
	if uint64(self.remaining()) < n {
		self.refuse("ends inside a value")
		return nil
	}
	taken := self.src[self.at : self.at+int(n)]
	self.at += int(n)
	return taken
}

func (self *oracleIndexReader) oneByte() byte {
	taken := self.take(1)
	if taken == nil {
		return 0
	}
	return taken[0]
}

// An unsigned LEB128 of at most 64 bits, minimal: at most ten bytes, the tenth at most 1, and no zero last byte after
// the first.
func (self *oracleIndexReader) vbyte() uint64 {
	value := uint64(0)
	for index := 0; ; index += 1 {
		b := self.oneByte()
		if self.err != nil {
			return 0
		}
		if index == 9 && 1 < b {
			self.refuse("has a VByte past 64 bits")
			return 0
		}
		value |= uint64(b&0x7f) << (7 * index)
		if b&0x80 == 0 {
			if 0 < index && b == 0 {
				self.refuse("has a VByte that is not minimal")
				return 0
			}
			return value
		}
		if index == 9 {
			self.refuse("has a VByte past ten bytes")
			return 0
		}
	}
}

// A text: VByte length, then valid UTF-8 within valueCap bytes.
func (self *oracleIndexReader) text(valueCap int) string {
	length := self.vbyte()
	if self.err == nil && uint64(valueCap) < length {
		self.refuse("has a text past its %d B cap", valueCap)
		return ""
	}
	value := self.take(length)
	if self.err == nil && !utf8.Valid(value) {
		self.refuse("has a text that is not UTF-8")
	}
	return string(value)
}

func oracleIndexAppendVByte(dst []byte, value uint64) []byte {
	return binary.AppendUvarint(dst, value)
}

func oracleIndexVByteLength(value uint64) int {
	return len(binary.AppendUvarint(nil, value))
}

// The row a doc kind may hold, as the format refuses it.
func oracleIndexCheckRow(row *oracleIndexRow, companion bool) error {
	if row.docKind < oracleIndexDocFile || oracleIndexDocDerived < row.docKind {
		return fmt.Errorf("a row of doc kind %d", row.docKind)
	}
	registered := row.docKind == oracleIndexDocRecord || row.docKind == oracleIndexDocDerived
	// bits 0-2 and the cut bits of fields 1-4 (3-6) and the inexact locator (18); bits 8-17 on registered rows; never
	// bit 7, the body's
	allowed := uint64(0x7f) | 1<<18
	if registered {
		allowed |= uint64(0x3ff) << 8
	}
	if row.flags&^allowed != 0 {
		return fmt.Errorf("a row flag %#x its kind cannot set", row.flags&^allowed)
	}
	if row.docKind != oracleIndexDocDerived && (row.started != 0 || row.expires != 0) {
		return errors.New("times on a row that is not derived")
	}
	if (companion && len(row.refId) != 16) || (!companion && len(row.refId) != 0) {
		return errors.New("a row's ref_id where its root does not take one")
	}
	return nil
}

func (self *oracleIndexReader) row(companion bool, settings *OracleIndexFormatSettings) *oracleIndexRow {
	start := self.at
	row := &oracleIndexRow{docKind: self.oneByte()}
	row.flags = self.vbyte()
	row.size = self.vbyte()
	row.chunk = self.vbyte()
	row.trigrams = self.vbyte()
	row.started = self.vbyte()
	row.expires = self.vbyte()
	if companion {
		row.refId = bytes.Clone(self.take(16))
	}
	row.locator = self.text(settings.LocatorMaxByteCount)
	for _, field := range row.fieldNumbers() {
		fieldCap := settings.HeaderFieldMaxByteCount
		if 5 < field {
			fieldCap = settings.RegisteredFieldMaxByteCount
		}
		row.fields[field] = self.text(fieldCap)
	}
	if self.err != nil {
		return nil
	}
	if settings.RowMaxByteCount < self.at-start {
		self.refuse("has a row past %d B", settings.RowMaxByteCount)
		return nil
	}
	if err := oracleIndexCheckRow(row, companion); err != nil {
		self.refuse("has %v", err)
		return nil
	}
	return row
}

// A key set: VByte count, then VByte gaps, the first the first key + 1, none zero, every key within 24 bits.
func (self *oracleIndexReader) keySet(settings *OracleIndexFormatSettings) []uint32 {
	start := self.at
	count := self.vbyte()
	if self.err == nil && uint64(self.remaining()) < count {
		self.refuse("has a key count past its bytes")
	}
	if self.err != nil {
		return nil
	}
	keys := make([]uint32, 0, count)
	last := -1
	for range count {
		gap := self.vbyte()
		if self.err != nil {
			return nil
		}
		if gap == 0 || 0x1000000 < gap || 0xffffff < last+int(gap) {
			self.refuse("has a key gap out of range")
			return nil
		}
		last += int(gap)
		keys = append(keys, uint32(last))
	}
	if settings.KeySetMaxByteCount < self.at-start {
		self.refuse("has a key set past its cap")
		return nil
	}
	return keys
}

func (self *oracleIndexReader) entry(companion bool, settings *OracleIndexFormatSettings) *oracleIndexEntry {
	entry := &oracleIndexEntry{kind: self.oneByte()}
	copy(entry.key[:], self.take(16))
	entry.version = self.vbyte()
	entry.timeSeconds = self.vbyte()
	switch entry.kind {
	case oracleIndexEntryFull:
		entry.row = self.row(companion, settings)
		entry.keys = self.keySet(settings)
		if self.err == nil && entry.row.trigrams != uint64(len(entry.keys)) {
			self.refuse("has a full entry whose trigram count is not its key set's")
		}
	case oracleIndexEntryTombstone:
	case oracleIndexEntryRefTombstone:
		if !companion {
			self.refuse("has a ref tombstone outside ur/index")
		}
	default:
		// 2, a diff's until owner decision 584, stays reserved and is refused as any unknown kind is (QD-1036)
		self.refuse("has an entry of kind %d", entry.kind)
	}
	if self.err != nil {
		return nil
	}
	return entry
}

// Whether a message holds a field its schema does not, at any depth.
func oracleIndexUnknownFields(message protoreflect.Message) bool {
	if 0 < len(message.GetUnknown()) {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.IsList() && field.Message() != nil:
			list := value.List()
			for index := range list.Len() {
				if oracleIndexUnknownFields(list.Get(index).Message()) {
					unknown = true
				}
			}
		case field.Message() != nil && !field.IsMap():
			unknown = unknown || oracleIndexUnknownFields(value.Message())
		}
		return !unknown
	})
	return unknown
}

// The bytes, unmarshaled into message, which must marshal again to the same bytes with nothing unknown in it.
func oracleIndexSmall(plaintext []byte, message proto.Message) error {
	if err := proto.Unmarshal(plaintext, message); err != nil {
		return fmt.Errorf("does not parse: %w", err)
	}
	if oracleIndexUnknownFields(message.ProtoReflect()) {
		return errors.New("holds a field format 1 does not have")
	}
	again, err := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	if err != nil {
		return err
	}
	if !bytes.Equal(again, plaintext) {
		return errors.New("does not marshal again to its bytes")
	}
	return nil
}

// Whether keys, as compare orders them, ascend strictly.
func oracleIndexStrictlySorted[T any](items []T, compare func(a T, b T) int) bool {
	for index := 1; index < len(items); index += 1 {
		if 0 <= compare(items[index-1], items[index]) {
			return false
		}
	}
	return true
}

// One index file version, read: what its path names, decoded, or why it is not format 1's canonical encoding of what
// it holds. A format above 1 reads as newer and is not decoded further.
func oracleIndexDecode(path string, plaintext []byte, settings *OracleIndexFormatSettings) (*oracleIndexFile, error) {
	parsed, ok := oracleIndexParsePath(path, settings)
	if !ok {
		return nil, fmt.Errorf("%s is no index path of format 1", path)
	}
	file := &oracleIndexFile{path: parsed}
	var err error
	switch parsed.kind {
	case oracleIndexPathSettings:
		file.settingsFile = &protocol.IndexSettings{}
		err = oracleIndexSmall(plaintext, file.settingsFile)
		if err == nil && file.settingsFile.WindowDays != 0 && (file.settingsFile.WindowDays < 7 || 365 < file.settingsFile.WindowDays) {
			err = fmt.Errorf("names a %d-day window", file.settingsFile.WindowDays)
		}
	case oracleIndexPathLock:
		file.lock = &protocol.IndexLock{}
		err = oracleIndexSmall(plaintext, file.lock)
	case oracleIndexPathAllManifest, oracleIndexPathBucketManifest:
		file.manifest = &protocol.IndexManifest{}
		err = oracleIndexSmall(plaintext, file.manifest)
		if err == nil {
			err = oracleIndexCheckManifest(parsed, file.manifest)
		}
	case oracleIndexPathErasureSet:
		file.erasureSet = &protocol.IndexErasureSet{}
		err = oracleIndexSmall(plaintext, file.erasureSet)
		if err == nil {
			err = oracleIndexCheckErasureSet(file.erasureSet)
		}
	default:
		err = oracleIndexDecodeFramed(file, plaintext, settings)
	}
	if err != nil {
		return nil, fmt.Errorf("%s (%s): %w", path, parsed.kind, err)
	}
	return file, nil
}

func oracleIndexCheckManifest(path oracleIndexPath, manifest *protocol.IndexManifest) error {
	if path.kind == oracleIndexPathBucketManifest && (manifest.StartDay != path.bucket || manifest.Days == 0 || manifest.RolledThroughDay != 0) {
		return errors.New("is not its path's bucket's manifest")
	}
	if path.kind == oracleIndexPathAllManifest && (manifest.StartDay != 0 || manifest.Days != 0 || 0 < len(manifest.Absorbed)) {
		return errors.New("is all's manifest with a bucket's fields")
	}
	if !oracleIndexStrictlySorted(manifest.Shards, func(a *protocol.IndexShard, b *protocol.IndexShard) int {
		return int(a.N) - int(b.N)
	}) {
		return errors.New("lists shards out of order or twice")
	}
	if !oracleIndexStrictlySorted(manifest.Absorbed, func(a *protocol.IndexWatermark, b *protocol.IndexWatermark) int {
		return bytes.Compare(a.WriterSidecarId, b.WriterSidecarId)
	}) {
		return errors.New("lists watermarks out of order or twice")
	}
	for _, watermark := range manifest.Absorbed {
		if watermark.Seq == 0 {
			return errors.New("lists a watermark of 0")
		}
	}
	return nil
}

func oracleIndexCheckErasureSet(erasureSet *protocol.IndexErasureSet) error {
	if !oracleIndexStrictlySorted(erasureSet.Erasures, func(a *protocol.IndexErasure, b *protocol.IndexErasure) int {
		return bytes.Compare(a.ErasureId, b.ErasureId)
	}) {
		return errors.New("lists erasures out of order or twice")
	}
	for _, erasure := range erasureSet.Erasures {
		if !oracleIndexStrictlySorted(erasure.Docs, func(a *protocol.IndexErased, b *protocol.IndexErased) int {
			return bytes.Compare(a.DocKey, b.DocKey)
		}) {
			return errors.New("lists an erasure's documents out of order or twice")
		}
		for _, doc := range erasure.Docs {
			if len(doc.DocKey) != 16 {
				return errors.New("lists a doc_key that is not 16 bytes")
			}
		}
	}
	return nil
}

// A slot, large entry or shard: "URix" | VByte header length | IndexFileHeader | body | zero pad.
func oracleIndexDecodeFramed(file *oracleIndexFile, plaintext []byte, settings *OracleIndexFormatSettings) error {
	if settings.PaddedFileMaxByteCount < len(plaintext) {
		return fmt.Errorf("is %d B, past %d", len(plaintext), settings.PaddedFileMaxByteCount)
	}
	reader := &oracleIndexReader{src: plaintext}
	if !bytes.Equal(reader.take(uint64(len(oracleIndexMagic))), []byte(oracleIndexMagic)) {
		return errors.New("has no URix")
	}
	headerBytes := reader.take(reader.vbyte())
	if reader.err != nil {
		return reader.err
	}
	header := &protocol.IndexFileHeader{}
	if err := proto.Unmarshal(headerBytes, header); err != nil {
		return errors.New("has a header that does not parse")
	}
	if oracleIndexFormatVersion < header.Format {
		file.newer = true
		return nil
	}
	if err := oracleIndexSmall(headerBytes, header); err != nil {
		return fmt.Errorf("has a header that %w", err)
	}
	file.header = header
	if header.Format != oracleIndexFormatVersion || header.Normalizer != oracleIndexNormalizer || header.Extractor != oracleIndexExtractor ||
		header.UnicodeVersion == "" || header.TextModuleVersion == "" {
		return errors.New("has a header naming no format, normalizer, extractor or tables")
	}
	if uint64(reader.remaining()) < uint64(header.BodyLength) {
		return errors.New("has a body past its bytes")
	}
	body := &oracleIndexReader{src: reader.take(uint64(header.BodyLength))}
	for _, b := range reader.src[reader.at:] {
		if b != 0 {
			return errors.New("has a pad byte that is not zero")
		}
	}
	file.padByteCount = reader.remaining()
	switch file.path.kind {
	case oracleIndexPathSlot, oracleIndexPathLargeEntry:
		return oracleIndexDecodeSlot(file, body, len(plaintext), settings)
	default:
		if settings.ShardMaxByteCount < reader.at {
			return fmt.Errorf("is %d B before its pad, past %d", reader.at, settings.ShardMaxByteCount)
		}
		return oracleIndexDecodeShard(file, body, settings)
	}
}

func oracleIndexDecodeSlot(file *oracleIndexFile, body *oracleIndexReader, length int, settings *OracleIndexFormatSettings) error {
	header := file.header
	wantType := uint32(oracleIndexTypeSlot)
	fileCap := settings.SlotFileMaxByteCount
	if file.path.kind == oracleIndexPathLargeEntry {
		wantType = oracleIndexTypeLargeEntry
		fileCap = settings.PaddedFileMaxByteCount
	}
	if header.Type != wantType || header.BucketStartDay != file.path.bucket || header.BucketDays == 0 ||
		!bytes.Equal(header.WriterSidecarId, file.path.writer[:]) || header.Seq == 0 ||
		(file.path.kind == oracleIndexPathLargeEntry && header.Seq != file.path.seq) ||
		header.PadGeneration != 0 || header.Tombstones != 0 {
		return errors.New("has a header that is not its path's")
	}
	if !oracleIndexStrictlySorted(header.Coverage, func(a *protocol.IndexCoverage, b *protocol.IndexCoverage) int {
		if c := bytes.Compare(a.RefId, b.RefId); c != 0 {
			return c
		}
		return oracleIndexBoolOrder(a.Horizon) - oracleIndexBoolOrder(b.Horizon)
	}) {
		return errors.New("has coverage out of order or twice")
	}
	if fileCap < length {
		return fmt.Errorf("is %d B, past its %d B cap", length, fileCap)
	}
	for range header.Count {
		start := body.at
		entry := body.entry(file.path.companion, settings)
		if body.err != nil {
			return body.err
		}
		entryByteCount := body.at - start
		if file.path.kind == oracleIndexPathSlot && settings.SlotEntryMaxByteCount < entryByteCount {
			return fmt.Errorf("has a %d B entry in a slot", entryByteCount)
		}
		if file.path.kind == oracleIndexPathLargeEntry && (entryByteCount <= settings.SlotEntryMaxByteCount || !entry.live()) {
			return errors.New("is a large entry that is not one full entry over a slot's")
		}
		if count := len(file.entries); 0 < count && 0 <= bytes.Compare(file.entries[count-1].key[:], entry.key[:]) {
			return errors.New("has entries out of order or repeated")
		}
		file.entries = append(file.entries, entry)
	}
	if body.remaining() != 0 {
		return errors.New("has bytes past its last entry")
	}
	if file.path.kind == oracleIndexPathLargeEntry && (1 < len(file.entries) || len(file.entries) == 0 && file.padByteCount == 0) {
		return errors.New("is a large entry holding more than one entry, or none and no pad")
	}
	return nil
}

func oracleIndexBoolOrder(value bool) int {
	if value {
		return 1
	}
	return 0
}

func oracleIndexDecodeShard(file *oracleIndexFile, body *oracleIndexReader, settings *OracleIndexFormatSettings) error {
	header := file.header
	switch file.path.kind {
	case oracleIndexPathBucketShard:
		if header.Type != oracleIndexTypeBucketShard || header.BucketStartDay != file.path.bucket || header.BucketDays == 0 {
			return errors.New("has a header that is not its bucket's shard's")
		}
	case oracleIndexPathAllShard:
		if header.Type != oracleIndexTypeAllShard || header.BucketStartDay != 0 || header.BucketDays != 0 || header.Tombstones != 0 {
			return errors.New("has a header that is not an all shard's")
		}
	}
	if len(header.WriterSidecarId) != 0 || header.Seq != 0 || len(header.Coverage) != 0 || header.PadGeneration == 0 {
		return errors.New("has a head's fields, or no pad generation")
	}
	for range header.Count {
		document := &oracleIndexEntry{kind: oracleIndexEntryFull}
		copy(document.key[:], body.take(16))
		document.version = body.vbyte()
		document.timeSeconds = body.vbyte()
		document.row = body.row(file.path.companion, settings)
		if body.err != nil {
			return body.err
		}
		if count := len(file.documents); 0 < count && 0 <= bytes.Compare(file.documents[count-1].key[:], document.key[:]) {
			return errors.New("has documents out of order or repeated")
		}
		file.documents = append(file.documents, document)
	}
	keyKinds := map[[16]byte]bool{}
	for _, document := range file.documents {
		keyKinds[document.key] = true
	}
	for range header.Tombstones {
		tombstone := &oracleIndexEntry{kind: body.oneByte()}
		copy(tombstone.key[:], body.take(16))
		tombstone.version = body.vbyte()
		tombstone.timeSeconds = body.vbyte()
		if body.err != nil {
			return body.err
		}
		switch {
		case tombstone.kind == oracleIndexEntryTombstone:
		case tombstone.kind == oracleIndexEntryRefTombstone && file.path.companion:
		default:
			return fmt.Errorf("has a tombstone of kind %d", tombstone.kind)
		}
		if count := len(file.tombstones); 0 < count && 0 <= oracleIndexCompareTombstones(file.tombstones[count-1], tombstone) {
			return errors.New("has tombstones out of order or repeated")
		}
		if keyKinds[tombstone.key] {
			return errors.New("has a key in both of its tables, or twice")
		}
		keyKinds[tombstone.key] = true
		file.tombstones = append(file.tombstones, tombstone)
	}
	return oracleIndexDecodeDictionary(file, body, settings)
}

func oracleIndexCompareTombstones(a *oracleIndexEntry, b *oracleIndexEntry) int {
	if a.kind != b.kind {
		return int(a.kind) - int(b.kind)
	}
	return bytes.Compare(a.key[:], b.key[:])
}

// One key of a dictionary.
type oracleIndexDictionaryKey struct {
	key           uint32
	bitset        bool
	documentCount uint64
	listByteCount uint64
}

func oracleIndexTrigramBytes(key uint32) [3]byte {
	return [3]byte{byte(key >> 16), byte(key >> 8), byte(key)}
}

// The leading bytes two distinct keys share, at most 2.
func oracleIndexSharedPrefix(previous uint32, key uint32) int {
	a, b := oracleIndexTrigramBytes(previous), oracleIndexTrigramBytes(key)
	prefix := 0
	for prefix < 2 && a[prefix] == b[prefix] {
		prefix += 1
	}
	return prefix
}

func oracleIndexDecodeDictionary(file *oracleIndexFile, body *oracleIndexReader, settings *OracleIndexFormatSettings) error {
	blockCount := body.vbyte()
	if body.err == nil && uint64(body.remaining()/5) < blockCount {
		body.refuse("has a block count past its bytes")
	}
	if body.err != nil {
		return body.err
	}
	type block struct {
		firstKey      uint32
		entriesOffset uint64
		listOffset    uint64
	}
	blocks := make([]block, 0, blockCount)
	for range blockCount {
		keyBytes := body.take(3)
		entriesOffset := body.vbyte()
		listOffset := body.vbyte()
		if body.err != nil {
			return body.err
		}
		next := block{firstKey: uint32(keyBytes[0])<<16 | uint32(keyBytes[1])<<8 | uint32(keyBytes[2]), entriesOffset: entriesOffset, listOffset: listOffset}
		if len(blocks) == 0 && (entriesOffset != 0 || listOffset != 0) {
			return errors.New("has a first block whose offsets are not zero")
		}
		if 0 < len(blocks) {
			last := blocks[len(blocks)-1]
			if next.firstKey <= last.firstKey || next.entriesOffset <= last.entriesOffset || next.listOffset <= last.listOffset {
				return errors.New("has a block index out of order")
			}
		}
		blocks = append(blocks, next)
	}
	if blockCount == 0 {
		if body.remaining() != 0 {
			return errors.New("has postings and no dictionary")
		}
		return nil
	}
	if len(file.documents) == 0 {
		return errors.New("has keys and no document")
	}
	entriesStart := body.at
	keys := []oracleIndexDictionaryKey{}
	listTotal := uint64(0)
	for index, current := range blocks {
		if uint64(body.at-entriesStart) != current.entriesOffset {
			return fmt.Errorf("has block %d's entries at another offset", index)
		}
		if listTotal != current.listOffset {
			return fmt.Errorf("has block %d's lists at another offset", index)
		}
		count := 0
		previous := uint32(0)
		for {
			if count == settings.BlockKeyCount {
				return fmt.Errorf("has a block of more than %d keys", settings.BlockKeyCount)
			}
			flag := body.oneByte()
			if body.err != nil {
				return body.err
			}
			if flag&^(oracleIndexPrefixMask|oracleIndexBitsetFlag) != 0 {
				return errors.New("has a key entry flag with a spare bit set")
			}
			prefix := int(flag & oracleIndexPrefixMask)
			keyBytes := oracleIndexTrigramBytes(previous)
			if count == 0 {
				if prefix != 0 {
					return errors.New("has a block's first key sharing a prefix")
				}
			} else if 2 < prefix {
				return errors.New("has a key repeated in its block")
			}
			copy(keyBytes[prefix:], body.take(uint64(3-prefix)))
			entry := oracleIndexDictionaryKey{
				key:    uint32(keyBytes[0])<<16 | uint32(keyBytes[1])<<8 | uint32(keyBytes[2]),
				bitset: flag&oracleIndexBitsetFlag != 0,
			}
			entry.documentCount = body.vbyte()
			entry.listByteCount = body.vbyte()
			if body.err != nil {
				return body.err
			}
			if count == 0 && entry.key != current.firstKey {
				return fmt.Errorf("has block %d's first key unlike its index's", index)
			}
			if 0 < count && (entry.key <= previous || oracleIndexSharedPrefix(previous, entry.key) != prefix) {
				return errors.New("has a key out of order or not at its longest shared prefix")
			}
			if 0 < len(keys) && entry.key <= keys[len(keys)-1].key {
				return errors.New("has keys out of order across blocks")
			}
			keys = append(keys, entry)
			listTotal += entry.listByteCount
			previous = entry.key
			count += 1
			if index < len(blocks)-1 {
				if uint64(body.at-entriesStart) == blocks[index+1].entriesOffset {
					break
				}
				if blocks[index+1].entriesOffset < uint64(body.at-entriesStart) {
					return fmt.Errorf("has block %d's entries past block %d's", index, index+1)
				}
				continue
			}
			// the last block's entries end where the postings start, and the postings where the body does
			if uint64(body.remaining()) == listTotal {
				break
			}
			if uint64(body.remaining()) < listTotal {
				return errors.New("has lists past its body")
			}
		}
		file.blockKeyCounts = append(file.blockKeyCounts, count)
	}
	documentCount := len(file.documents)
	keySets := make([][]uint32, documentCount)
	for _, key := range keys {
		docIds, err := oracleIndexDecodeList(body.take(key.listByteCount), key.bitset, key.documentCount, documentCount)
		if body.err != nil {
			return body.err
		}
		if err != nil {
			return err
		}
		for _, docId := range docIds {
			keySets[docId] = append(keySets[docId], key.key)
		}
	}
	for docId, document := range file.documents {
		document.keys = keySets[docId]
		if document.row.trigrams != uint64(len(document.keys)) {
			return fmt.Errorf("has document %d's trigram count unlike its postings", docId)
		}
	}
	return nil
}

func oracleIndexBitsetByteCount(documentCount int) int {
	return (documentCount + 7) / 8
}

func oracleIndexGapByteCount(docIds []uint32) int {
	byteCount := 0
	last := -1
	for _, docId := range docIds {
		byteCount += oracleIndexVByteLength(uint64(int(docId) - last))
		last = int(docId)
	}
	return byteCount
}

// A list's docids: a bitset of ⌈N/8⌉ bytes where that is strictly shorter than its gaps, else gaps, each in its own
// canonical form.
func oracleIndexDecodeList(encoded []byte, bitset bool, listCount uint64, documentCount int) ([]uint32, error) {
	if listCount == 0 || uint64(documentCount) < listCount {
		return nil, errors.New("has a list's document count out of range")
	}
	docIds := []uint32{}
	if bitset {
		if len(encoded) != oracleIndexBitsetByteCount(documentCount) {
			return nil, errors.New("has a bitset that is not its shard's length")
		}
		for index, b := range encoded {
			for bit := range 8 {
				if b&(1<<bit) == 0 {
					continue
				}
				docId := index*8 + bit
				if documentCount <= docId {
					return nil, errors.New("has a bitset's spare bit set")
				}
				docIds = append(docIds, uint32(docId))
			}
		}
		if uint64(len(docIds)) != listCount {
			return nil, errors.New("has a bitset that does not hold its document count")
		}
		if oracleIndexGapByteCount(docIds) <= len(encoded) {
			return nil, errors.New("has a bitset where gaps are no longer")
		}
		return docIds, nil
	}
	if oracleIndexBitsetByteCount(documentCount) < len(encoded) {
		return nil, errors.New("has gaps longer than a bitset")
	}
	reader := &oracleIndexReader{src: encoded}
	last := -1
	for range listCount {
		gap := reader.vbyte()
		if reader.err != nil {
			return nil, reader.err
		}
		if gap == 0 || uint64(documentCount) < uint64(last)+gap+1 {
			return nil, errors.New("has a list gap out of range")
		}
		last += int(gap)
		docIds = append(docIds, uint32(last))
	}
	if reader.remaining() != 0 {
		return nil, errors.New("has bytes past a list's gaps")
	}
	return docIds, nil
}

// --- writing ---

func oracleIndexAppendRow(dst []byte, row *oracleIndexRow) []byte {
	dst = append(dst, row.docKind)
	for _, value := range []uint64{row.flags, row.size, row.chunk, row.trigrams, row.started, row.expires} {
		dst = oracleIndexAppendVByte(dst, value)
	}
	dst = append(dst, row.refId...)
	dst = oracleIndexAppendVByte(dst, uint64(len(row.locator)))
	dst = append(dst, row.locator...)
	for _, field := range row.fieldNumbers() {
		dst = oracleIndexAppendVByte(dst, uint64(len(row.fields[field])))
		dst = append(dst, row.fields[field]...)
	}
	return dst
}

func oracleIndexAppendKeySet(dst []byte, keys []uint32) []byte {
	dst = oracleIndexAppendVByte(dst, uint64(len(keys)))
	last := -1
	for _, key := range keys {
		dst = oracleIndexAppendVByte(dst, uint64(int(key)-last))
		last = int(key)
	}
	return dst
}

func oracleIndexAppendEntry(dst []byte, entry *oracleIndexEntry) []byte {
	dst = append(dst, entry.kind)
	dst = append(dst, entry.key[:]...)
	dst = oracleIndexAppendVByte(dst, entry.version)
	dst = oracleIndexAppendVByte(dst, entry.timeSeconds)
	if entry.kind == oracleIndexEntryFull {
		dst = oracleIndexAppendRow(dst, entry.row)
		dst = oracleIndexAppendKeySet(dst, entry.keys)
	}
	return dst
}

// The framed file around body: the magic, the header with body_length set, the body and the pad.
func oracleIndexFrame(header *protocol.IndexFileHeader, body []byte, padByteCount int) ([]byte, error) {
	header = proto.CloneOf(header)
	header.BodyLength = uint32(len(body))
	encodedHeader, err := proto.MarshalOptions{Deterministic: true}.Marshal(header)
	if err != nil {
		return nil, err
	}
	file := []byte(oracleIndexMagic)
	file = oracleIndexAppendVByte(file, uint64(len(encodedHeader)))
	file = append(file, encodedHeader...)
	file = append(file, body...)
	return append(file, make([]byte, padByteCount)...), nil
}

// A shard's body as the format orders it, blocked as blockKeyCounts says, or by the format's block size where nil.
func oracleIndexShardBody(documents []*oracleIndexEntry, tombstones []*oracleIndexEntry, blockKeyCounts []int, settings *OracleIndexFormatSettings) ([]byte, error) {
	documents = slices.Clone(documents)
	slices.SortFunc(documents, func(a *oracleIndexEntry, b *oracleIndexEntry) int { return bytes.Compare(a.key[:], b.key[:]) })
	tombstones = slices.Clone(tombstones)
	slices.SortFunc(tombstones, oracleIndexCompareTombstones)
	body := []byte{}
	keyDocIds := map[uint32][]uint32{}
	for docId, document := range documents {
		body = append(body, document.key[:]...)
		body = oracleIndexAppendVByte(body, document.version)
		body = oracleIndexAppendVByte(body, document.timeSeconds)
		body = oracleIndexAppendRow(body, document.row)
		for _, key := range document.keys {
			keyDocIds[key] = append(keyDocIds[key], uint32(docId))
		}
	}
	for _, tombstone := range tombstones {
		body = append(body, tombstone.kind)
		body = append(body, tombstone.key[:]...)
		body = oracleIndexAppendVByte(body, tombstone.version)
		body = oracleIndexAppendVByte(body, tombstone.timeSeconds)
	}
	keys := slices.Sorted(func(yield func(uint32) bool) {
		for key := range keyDocIds {
			if !yield(key) {
				return
			}
		}
	})
	partition := blockKeyCounts
	if partition == nil {
		for remaining := len(keys); 0 < remaining; remaining -= settings.BlockKeyCount {
			partition = append(partition, min(remaining, settings.BlockKeyCount))
		}
	}
	total := 0
	for _, count := range partition {
		total += count
	}
	if total != len(keys) {
		return nil, fmt.Errorf("a partition of %d keys for %d", total, len(keys))
	}
	postings := []byte{}
	entries := []byte{}
	index := []byte{}
	next := 0
	for _, count := range partition {
		firstKey := oracleIndexTrigramBytes(keys[next])
		index = append(index, firstKey[:]...)
		index = oracleIndexAppendVByte(index, uint64(len(entries)))
		index = oracleIndexAppendVByte(index, uint64(len(postings)))
		for at := next; at < next+count; at += 1 {
			key := keys[at]
			docIds := keyDocIds[key]
			listStart := len(postings)
			bitset := oracleIndexBitsetByteCount(len(documents)) < oracleIndexGapByteCount(docIds)
			if bitset {
				set := make([]byte, oracleIndexBitsetByteCount(len(documents)))
				for _, docId := range docIds {
					set[docId/8] |= 1 << (docId % 8)
				}
				postings = append(postings, set...)
			} else {
				last := -1
				for _, docId := range docIds {
					postings = oracleIndexAppendVByte(postings, uint64(int(docId)-last))
					last = int(docId)
				}
			}
			prefix := 0
			if at != next {
				prefix = oracleIndexSharedPrefix(keys[at-1], key)
			}
			flag := byte(prefix)
			if bitset {
				flag |= oracleIndexBitsetFlag
			}
			entries = append(entries, flag)
			keyBytes := oracleIndexTrigramBytes(key)
			entries = append(entries, keyBytes[prefix:]...)
			entries = oracleIndexAppendVByte(entries, uint64(len(docIds)))
			entries = oracleIndexAppendVByte(entries, uint64(len(postings)-listStart))
		}
		next += count
	}
	body = oracleIndexAppendVByte(body, uint64(len(partition)))
	body = append(body, index...)
	body = append(body, entries...)
	return append(body, postings...), nil
}

// The file's canonical bytes: what a writer of format 1 writes holding what file holds, its partition and pad as file
// has them.
func oracleIndexEncode(file *oracleIndexFile, settings *OracleIndexFormatSettings) ([]byte, error) {
	switch file.path.kind {
	case oracleIndexPathSettings:
		return proto.MarshalOptions{Deterministic: true}.Marshal(file.settingsFile)
	case oracleIndexPathLock:
		return proto.MarshalOptions{Deterministic: true}.Marshal(file.lock)
	case oracleIndexPathAllManifest, oracleIndexPathBucketManifest:
		return proto.MarshalOptions{Deterministic: true}.Marshal(file.manifest)
	case oracleIndexPathErasureSet:
		return proto.MarshalOptions{Deterministic: true}.Marshal(file.erasureSet)
	case oracleIndexPathSlot, oracleIndexPathLargeEntry:
		entries := slices.Clone(file.entries)
		slices.SortFunc(entries, func(a *oracleIndexEntry, b *oracleIndexEntry) int { return bytes.Compare(a.key[:], b.key[:]) })
		body := []byte{}
		for _, entry := range entries {
			body = oracleIndexAppendEntry(body, entry)
		}
		header := proto.CloneOf(file.header)
		header.Count = uint32(len(entries))
		return oracleIndexFrame(header, body, file.padByteCount)
	case oracleIndexPathBucketShard, oracleIndexPathAllShard:
		body, err := oracleIndexShardBody(file.documents, file.tombstones, file.blockKeyCounts, settings)
		if err != nil {
			return nil, err
		}
		header := proto.CloneOf(file.header)
		header.Count = uint32(len(file.documents))
		header.Tombstones = uint32(len(file.tombstones))
		return oracleIndexFrame(header, body, file.padByteCount)
	}
	return nil, fmt.Errorf("no index file of kind %d", file.path.kind)
}

// Padmé's step at length: 2^(E - S), E = ⌊log2 L⌋, S = ⌊log2 E⌋ + 1; a length below 4 is its own.
func oracleIndexPadmeStep(length int) int {
	if length < 4 {
		return 1
	}
	exponent := bits.Len64(uint64(length)) - 1
	return 1 << (exponent - bits.Len64(uint64(exponent)))
}

// §11.14's keyed pad after a shard's unpadded bytes, under K_index_g: u32be(HMAC-SHA256(K_index_g, "pad" ||
// SHA-256(unpadded))[0:4]) mod step(len(unpadded)).
func oracleIndexKeyedPad(indexKey []byte, unpadded []byte) int {
	digest := sha256.Sum256(unpadded)
	mac := hmac.New(sha256.New, indexKey)
	mac.Write([]byte(oracleIndexPadLabel))
	mac.Write(digest[:])
	return int(binary.BigEndian.Uint32(mac.Sum(nil)[:4]) % uint32(oracleIndexPadmeStep(len(unpadded))))
}

// K_index_g of a repo key's generation (§10.5's index purpose, no further context).
func oracleIndexKey(repoKey *sidecar.EvsRepoKey) ([]byte, error) {
	return repoKey.DeriveKey(sidecar.EvsKeyPurposeIndex, nil)
}

// --- the check ---

// The settings FI-22 and the search checks read the index with.
type Fi22Settings struct {
	Format *OracleIndexFormatSettings
}

func DefaultFi22Settings() *Fi22Settings {
	return &Fi22Settings{Format: DefaultOracleIndexFormatSettings()}
}

// FI-22 over every source's history: see the file header. Each push is judged once, at the first check that sees it.
func checkFi22(ctx context.Context, oracle *Oracle) error {
	errs := []error{}
	for _, replay := range searchReplaysOf(ctx, oracle) {
		if replay.readErr != nil {
			errs = append(errs, fmt.Errorf("%s: %w", replay.name, replay.readErr))
			continue
		}
		errs = append(errs, replay.fi22Findings...)
	}
	return errors.Join(errs...)
}

// FI-22's findings for one written file version: its read, its hash and its blocks and pad. read is the decoded file
// or nil when it did not decode, in which case err names why.
func fi22Judge(push *SearchIndexPush, written *SearchIndexFile, read *oracleIndexFile, readErr error, keys SearchIndexKeys, settings *OracleIndexFormatSettings) []error {
	errs := []error{}
	at := fmt.Sprintf("version %d of %s, written at ref version %d", written.Version, written.Path, push.RefVersion)
	if written.ContentSha256 != nil {
		digest := sha256.Sum256(written.Plaintext)
		if !bytes.Equal(digest[:], written.ContentSha256) {
			errs = append(errs, fmt.Errorf("%s: its content_sha256 is not its plaintext's", at))
		}
	}
	if readErr != nil {
		return append(errs, fmt.Errorf("%s is not format 1's canonical encoding: %w", at, readErr))
	}
	if read.newer {
		return errs
	}
	again, err := oracleIndexEncode(read, settings)
	if err != nil {
		return append(errs, fmt.Errorf("%s: %w", at, err))
	}
	if !bytes.Equal(again, written.Plaintext) {
		return append(errs, fmt.Errorf("%s does not encode again to its bytes: %d B written, %d B canonical, first difference at %d",
			at, len(written.Plaintext), len(again), fi22FirstDifference(again, written.Plaintext)))
	}
	if read.path.kind != oracleIndexPathBucketShard && read.path.kind != oracleIndexPathAllShard {
		return errs
	}
	rewrite := push.Kind == SearchIndexPushClosure || push.Kind == SearchIndexPushDrop
	if !rewrite {
		for index, count := range read.blockKeyCounts {
			if count != settings.BlockKeyCount && index != len(read.blockKeyCounts)-1 {
				errs = append(errs, fmt.Errorf("%s blocks its keys by %v, not by %d", at, read.blockKeyCounts, settings.BlockKeyCount))
				break
			}
		}
	}
	if keys != nil && !rewrite {
		repoKey, err := keys.IndexRepoKey(read.header.PadGeneration)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: no key of generation %d: %w", at, read.header.PadGeneration, err))
		} else if indexKey, err := oracleIndexKey(repoKey); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", at, err))
		} else if unpadded := written.Plaintext[:len(written.Plaintext)-read.padByteCount]; oracleIndexKeyedPad(indexKey, unpadded) != read.padByteCount {
			errs = append(errs, fmt.Errorf("%s pads %d B, not its keyed pad of %d B", at, read.padByteCount, oracleIndexKeyedPad(indexKey, unpadded)))
		}
	}
	return errs
}

func fi22FirstDifference(a []byte, b []byte) int {
	for index := range min(len(a), len(b)) {
		if a[index] != b[index] {
			return index
		}
	}
	return min(len(a), len(b))
}
