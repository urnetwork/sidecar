//go:build !ios_extension

// An index root's paths and small files, and the check every fetched index file passes before it is kept (§11.14's
// paths, settings, lock, manifests and verify rows; protocol/INDEX-FORMAT.md's Paths and Small files).
//
// Paths are ASCII, sealed and tokenized as any path is (§11.7). <root> is .ur-index/i1 on a file-mode ref and i1 on
// ur/index, and a rebuild under a new normalizer or format writes i2 beside it; the erasure set x sits beside the
// roots. Numbers are decimal with no leading zero. All shards from 3,499 on sit in directories numbered from where
// the files stop (search-format-all-directory-names), so a directory's name is never a shard file's and nothing moves
// at the split.
//
// The small files are bare deterministic proto3, repeated fields sorted strictly, and a decoder refuses anything a
// re-marshal does not reproduce or that carries a field format 1 does not have.

package sidecar

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/urnetwork/sidecar/protocol"
)

// Where an index root sits: under .ur-index/ on a file-mode ref, at the top of ur/index.
const (
	indexFileModePrefix = ".ur-index/"
	indexRootPrefix     = "i"
	indexErasureSetName = "x"
)

// The root normalizer 1 and format 1 write.
const indexRootNumber = 1

// a/ holds shards 0 to 3,498 as files beside m; from 3,499 a shard sits in a/<k>/, 1,000 a directory.
const (
	indexAllFileShardCount      = 3499
	indexAllDirectoryShardCount = 1000
)

// A writer's slots in a bucket, k 0-15 (§11.14's caps row).
const indexWriterSlotCount = 16

// IndexSettings.window_days: 0 means 30, else 7-365 (§11.14's settings row).
const (
	indexDefaultWindowDays = 30
	indexMinWindowDays     = 7
	indexMaxWindowDays     = 365
)

// What an index path names.
type indexPathKind int

const (
	indexPathSettings indexPathKind = iota + 1
	indexPathLock
	indexPathAllManifest
	indexPathAllShard
	indexPathBucketManifest
	indexPathBucketShard
	indexPathSlot
	indexPathLargeEntry
	indexPathErasureSet
)

// One index path, parsed. Which fields mean anything follows from kind.
type indexPath struct {
	kind indexPathKind
	// Under ur/index's root, where rows carry their ref_id.
	companion       bool
	rootNumber      uint32
	bucketStartDay  uint32
	shardNumber     uint32
	writerSidecarId [indexIdByteCount]byte
	slotIndex       uint32
	seq             uint32
}

// Builds the paths under one index root.
type indexPaths struct {
	root string
}

// The paths of root number rootNumber on ur/index (companion) or on a file-mode ref.
func indexNewPaths(companion bool, rootNumber uint32) indexPaths {
	root := indexRootPrefix + strconv.FormatUint(uint64(rootNumber), 10)
	if !companion {
		root = indexFileModePrefix + root
	}
	return indexPaths{root: root}
}

// The erasure set beside a ref's roots.
func indexErasureSetPath(companion bool) string {
	if companion {
		return indexErasureSetName
	}
	return indexFileModePrefix + indexErasureSetName
}

// <root>/settings, the one versioned file.
func (self indexPaths) settings() string {
	return self.root + "/settings"
}

// <root>/lock, the roll-up's.
func (self indexPaths) lock() string {
	return self.root + "/lock"
}

// <root>/a/m.
func (self indexPaths) allManifest() string {
	return self.root + "/a/m"
}

// All shard n: a/<n> below 3,499, then a/<k>/<n> with k = 3,499 + ⌊(n - 3,499) / 1,000⌋.
func (self indexPaths) allShard(n uint32) string {
	if n < indexAllFileShardCount {
		return self.root + "/a/" + indexDecimal(n)
	}
	return self.root + "/a/" + indexDecimal(indexAllDirectory(n)) + "/" + indexDecimal(n)
}

// The directory of all shard n from 3,499 on.
func indexAllDirectory(n uint32) uint32 {
	return indexAllFileShardCount + (n-indexAllFileShardCount)/indexAllDirectoryShardCount
}

// <root>/b/<S>/m.
func (self indexPaths) bucketManifest(startDay uint32) string {
	return self.bucket(startDay) + "/m"
}

// <root>/b/<S>/s/<n>.
func (self indexPaths) bucketShard(startDay uint32, n uint32) string {
	return self.bucket(startDay) + "/s/" + indexDecimal(n)
}

// Slot k of a writer, k 0-15.
func (self indexPaths) slot(startDay uint32, writerSidecarId [indexIdByteCount]byte, k uint32) (string, error) {
	if indexWriterSlotCount <= k {
		return "", indexMalformed("a slot past a writer's 16")
	}
	return self.writer(startDay, writerSidecarId) + "/" + indexDecimal(k), nil
}

// A writer's large entry of seq, from 1.
func (self indexPaths) largeEntry(startDay uint32, writerSidecarId [indexIdByteCount]byte, seq uint32) (string, error) {
	if seq == 0 {
		return "", indexMalformed("a large entry of seq 0")
	}
	return self.writer(startDay, writerSidecarId) + "/L" + indexDecimal(seq), nil
}

// <root>/b/<S>.
func (self indexPaths) bucket(startDay uint32) string {
	return self.root + "/b/" + indexDecimal(startDay)
}

// b/<S>/w/<h>/<writer>: the sidecar_id in lowercase hex, and h its first two digits.
func (self indexPaths) writer(startDay uint32, writerSidecarId [indexIdByteCount]byte) string {
	writer := hex.EncodeToString(writerSidecarId[:])
	return self.bucket(startDay) + "/w/" + writer[:2] + "/" + writer
}

// n as the paths spell it.
func indexDecimal(n uint32) string {
	return strconv.FormatUint(uint64(n), 10)
}

// A number as the paths spell it, 0 or a decimal with no leading zero, within 32 bits.
func indexParseDecimal(text string) (uint32, bool) {
	if text == "" || (1 < len(text) && text[0] == '0') {
		return 0, false
	}
	for _, c := range []byte(text) {
		if c < '0' || '9' < c {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(text, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// Which index file path names on a ref, ur/index's when companion, and false for any path under an index root that is
// none of §11.14's own, which a reader ignores and alarms on (FI-17). Only the canonical spelling parses.
func indexParsePath(path string, companion bool) (indexPath, bool) {
	parsed := indexPath{companion: companion}
	if !companion {
		rest, ok := strings.CutPrefix(path, indexFileModePrefix)
		if !ok {
			return indexPath{}, false
		}
		path = rest
	}
	if path == indexErasureSetName {
		parsed.kind = indexPathErasureSet
		return parsed, true
	}
	parts := strings.Split(path, "/")
	rootNumber, ok := indexParseDecimal(strings.TrimPrefix(parts[0], indexRootPrefix))
	if !ok || !strings.HasPrefix(parts[0], indexRootPrefix) || rootNumber == 0 || len(parts) < 2 {
		return indexPath{}, false
	}
	parsed.rootNumber = rootNumber
	parts = parts[1:]
	switch {
	case len(parts) == 1 && parts[0] == "settings":
		parsed.kind = indexPathSettings
	case len(parts) == 1 && parts[0] == "lock":
		parsed.kind = indexPathLock
	case len(parts) == 2 && parts[0] == "a" && parts[1] == "m":
		parsed.kind = indexPathAllManifest
	case len(parts) == 2 && parts[0] == "a":
		n, ok := indexParseDecimal(parts[1])
		if !ok || indexAllFileShardCount <= n {
			return indexPath{}, false
		}
		parsed.kind = indexPathAllShard
		parsed.shardNumber = n
	case len(parts) == 3 && parts[0] == "a":
		k, kOk := indexParseDecimal(parts[1])
		n, nOk := indexParseDecimal(parts[2])
		if !kOk || !nOk || n < indexAllFileShardCount || indexAllDirectory(n) != k {
			return indexPath{}, false
		}
		parsed.kind = indexPathAllShard
		parsed.shardNumber = n
	case 3 <= len(parts) && parts[0] == "b":
		startDay, ok := indexParseDecimal(parts[1])
		if !ok {
			return indexPath{}, false
		}
		parsed.bucketStartDay = startDay
		switch {
		case len(parts) == 3 && parts[2] == "m":
			parsed.kind = indexPathBucketManifest
		case len(parts) == 4 && parts[2] == "s":
			n, ok := indexParseDecimal(parts[3])
			if !ok {
				return indexPath{}, false
			}
			parsed.kind = indexPathBucketShard
			parsed.shardNumber = n
		case len(parts) == 6 && parts[2] == "w":
			writer := parts[4]
			id, err := hex.DecodeString(writer)
			if err != nil || len(id) != indexIdByteCount || writer != strings.ToLower(writer) || parts[3] != writer[:2] {
				return indexPath{}, false
			}
			parsed.writerSidecarId = [indexIdByteCount]byte(id)
			if seqText, ok := strings.CutPrefix(parts[5], "L"); ok {
				seq, ok := indexParseDecimal(seqText)
				if !ok || seq == 0 {
					return indexPath{}, false
				}
				parsed.kind = indexPathLargeEntry
				parsed.seq = seq
			} else {
				k, ok := indexParseDecimal(parts[5])
				if !ok || indexWriterSlotCount <= k {
					return indexPath{}, false
				}
				parsed.kind = indexPathSlot
				parsed.slotIndex = k
			}
		default:
			return indexPath{}, false
		}
	default:
		return indexPath{}, false
	}
	return parsed, true
}

// The path's spelling, which indexParsePath reads back.
func (self indexPath) String() string {
	if self.kind == indexPathErasureSet {
		return indexErasureSetPath(self.companion)
	}
	paths := indexNewPaths(self.companion, self.rootNumber)
	switch self.kind {
	case indexPathSettings:
		return paths.settings()
	case indexPathLock:
		return paths.lock()
	case indexPathAllManifest:
		return paths.allManifest()
	case indexPathAllShard:
		return paths.allShard(self.shardNumber)
	case indexPathBucketManifest:
		return paths.bucketManifest(self.bucketStartDay)
	case indexPathBucketShard:
		return paths.bucketShard(self.bucketStartDay, self.shardNumber)
	case indexPathSlot:
		path, _ := paths.slot(self.bucketStartDay, self.writerSidecarId, self.slotIndex)
		return path
	case indexPathLargeEntry:
		path, _ := paths.largeEntry(self.bucketStartDay, self.writerSidecarId, self.seq)
		return path
	}
	return ""
}

// Whether a message, or any message inside it, holds a field format 1 does not have.
func indexHasUnknownFields(message protoreflect.Message) bool {
	if len(message.GetUnknown()) != 0 {
		return true
	}
	unknown := false
	message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
		switch {
		case field.Message() == nil || field.IsMap():
		case field.IsList():
			list := value.List()
			for index := range list.Len() {
				if indexHasUnknownFields(list.Get(index).Message()) {
					unknown = true
				}
			}
		default:
			unknown = indexHasUnknownFields(value.Message())
		}
		return !unknown
	})
	return unknown
}

// A small file's bytes: the message marshaled deterministically.
func indexMarshalSmall(message proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(message)
}

// Reads a small file into message, refusing all but its one canonical encoding.
func indexUnmarshalSmall(file []byte, message proto.Message) error {
	if err := proto.Unmarshal(file, message); err != nil {
		return indexMalformed("a small file that does not parse")
	}
	if indexHasUnknownFields(message.ProtoReflect()) {
		return indexMalformed("a small file with a field format 1 does not have")
	}
	again, err := indexMarshalSmall(message)
	if err != nil || !bytes.Equal(again, file) {
		return indexMalformed("a small file that is not canonical")
	}
	return nil
}

// Refuses a window outside 0 or 7-365.
func indexCheckSettings(settings *protocol.IndexSettings) error {
	if settings.WindowDays != 0 && (settings.WindowDays < indexMinWindowDays || indexMaxWindowDays < settings.WindowDays) {
		return indexMalformed("a window outside 7-365 days")
	}
	return nil
}

// Writes settings, refusing a window it may not hold.
func indexEncodeSettings(settings *protocol.IndexSettings) ([]byte, error) {
	if err := indexCheckSettings(settings); err != nil {
		return nil, err
	}
	return indexMarshalSmall(settings)
}

// Reads settings, its one canonical encoding only.
func indexDecodeSettings(file []byte) (*protocol.IndexSettings, error) {
	settings := &protocol.IndexSettings{}
	if err := indexUnmarshalSmall(file, settings); err != nil {
		return nil, err
	}
	if err := indexCheckSettings(settings); err != nil {
		return nil, err
	}
	return settings, nil
}

// The window settings give, in days: 0 means 30.
func indexWindowDays(settings *protocol.IndexSettings) uint32 {
	if settings == nil || settings.WindowDays == 0 {
		return indexDefaultWindowDays
	}
	return settings.WindowDays
}

// A held lock names its holder, and a time it lapses at; a free one is the empty message, so it has one encoding.
func indexCheckLock(lock *protocol.IndexLock) error {
	if len(lock.HolderSidecarId) == 0 {
		if lock.BucketStartDay != 0 || lock.UntilMs != 0 {
			return indexMalformed("a free lock naming a bucket or a time")
		}
		return nil
	}
	if len(lock.HolderSidecarId) != indexIdByteCount || lock.UntilMs <= 0 {
		return indexMalformed("a held lock without its holder or time")
	}
	return nil
}

// Writes a lock, free or held.
func indexEncodeLock(lock *protocol.IndexLock) ([]byte, error) {
	if err := indexCheckLock(lock); err != nil {
		return nil, err
	}
	return indexMarshalSmall(lock)
}

// Reads a lock, its one canonical encoding only.
func indexDecodeLock(file []byte) (*protocol.IndexLock, error) {
	lock := &protocol.IndexLock{}
	if err := indexUnmarshalSmall(file, lock); err != nil {
		return nil, err
	}
	if err := indexCheckLock(lock); err != nil {
		return nil, err
	}
	return lock, nil
}

// A bucket's manifest names its window and absorbed seqs, and no roll-up; all's names no window and no seq. Shards
// are in document order, which is shard number order, since a new shard takes the highest n plus 1 and a join keeps
// the lower n; absorbed is by writer, one seq each from 1.
func indexCheckManifest(manifest *protocol.IndexManifest, all bool) error {
	if all {
		if manifest.StartDay != 0 || manifest.Days != 0 || len(manifest.Absorbed) != 0 {
			return indexMalformed("all's manifest naming a bucket's fields")
		}
	} else if manifest.Days == 0 || manifest.RolledThroughDay != 0 {
		return indexMalformed("a bucket's manifest without its window or naming a roll-up")
	}
	for index, shard := range manifest.Shards {
		if 0 < index && shard.N <= manifest.Shards[index-1].N {
			return indexMalformed("shards out of order or repeated")
		}
		if shard.LastDay < shard.FirstDay {
			return indexMalformed("a shard's days out of order")
		}
	}
	for index, watermark := range manifest.Absorbed {
		if len(watermark.WriterSidecarId) != indexIdByteCount || watermark.Seq == 0 {
			return indexMalformed("an absorbed seq without its writer")
		}
		if 0 < index && bytes.Compare(manifest.Absorbed[index-1].WriterSidecarId, watermark.WriterSidecarId) >= 0 {
			return indexMalformed("absorbed seqs out of order or repeated")
		}
	}
	return nil
}

// Writes a manifest, its repeated fields sorted first.
func indexEncodeManifest(manifest *protocol.IndexManifest, all bool) ([]byte, error) {
	sorted := proto.CloneOf(manifest)
	slices.SortFunc(sorted.Shards, func(a *protocol.IndexShard, b *protocol.IndexShard) int {
		return cmp.Compare(a.N, b.N)
	})
	slices.SortFunc(sorted.Absorbed, func(a *protocol.IndexWatermark, b *protocol.IndexWatermark) int {
		return bytes.Compare(a.WriterSidecarId, b.WriterSidecarId)
	})
	if err := indexCheckManifest(sorted, all); err != nil {
		return nil, err
	}
	return indexMarshalSmall(sorted)
}

// Reads a bucket's manifest or, when all is set, a/m, its one canonical encoding only.
func indexDecodeManifest(file []byte, all bool) (*protocol.IndexManifest, error) {
	manifest := &protocol.IndexManifest{}
	if err := indexUnmarshalSmall(file, manifest); err != nil {
		return nil, err
	}
	if err := indexCheckManifest(manifest, all); err != nil {
		return nil, err
	}
	return manifest, nil
}

// Erasures by id and each one's documents by doc_key, strictly, every id 16 bytes, and the whole at most 16,208 B.
func indexCheckErasureSet(erasureSet *protocol.IndexErasureSet) error {
	for index, erasure := range erasureSet.Erasures {
		if len(erasure.ErasureId) != indexIdByteCount || len(erasure.EraserSidecarId) != indexIdByteCount {
			return indexMalformed("an erasure without its ids")
		}
		if 0 < index && bytes.Compare(erasureSet.Erasures[index-1].ErasureId, erasure.ErasureId) >= 0 {
			return indexMalformed("erasures out of order or repeated")
		}
		for docIndex, erased := range erasure.Docs {
			if len(erased.DocKey) != indexIdByteCount {
				return indexMalformed("an erased document without its doc_key")
			}
			if 0 < docIndex && bytes.Compare(erasure.Docs[docIndex-1].DocKey, erased.DocKey) >= 0 {
				return indexMalformed("erased documents out of order or repeated")
			}
		}
	}
	return nil
}

// Writes an erasure set, its repeated fields sorted first.
func indexEncodeErasureSet(erasureSet *protocol.IndexErasureSet, settings *IndexFormatSettings) ([]byte, error) {
	sorted := proto.CloneOf(erasureSet)
	slices.SortFunc(sorted.Erasures, func(a *protocol.IndexErasure, b *protocol.IndexErasure) int {
		return bytes.Compare(a.ErasureId, b.ErasureId)
	})
	for _, erasure := range sorted.Erasures {
		slices.SortFunc(erasure.Docs, func(a *protocol.IndexErased, b *protocol.IndexErased) int {
			return bytes.Compare(a.DocKey, b.DocKey)
		})
	}
	if err := indexCheckErasureSet(sorted); err != nil {
		return nil, err
	}
	file, err := indexMarshalSmall(sorted)
	if err != nil {
		return nil, err
	}
	if settings.SlotMaxByteCount < len(file) {
		return nil, indexMalformed("an erasure set past a slot's cap")
	}
	return file, nil
}

// Reads an erasure set, its one canonical encoding only, within 16,208 B.
func indexDecodeErasureSet(file []byte, settings *IndexFormatSettings) (*protocol.IndexErasureSet, error) {
	if settings.SlotMaxByteCount < len(file) {
		return nil, indexMalformed("an erasure set past a slot's cap")
	}
	erasureSet := &protocol.IndexErasureSet{}
	if err := indexUnmarshalSmall(file, erasureSet); err != nil {
		return nil, err
	}
	if err := indexCheckErasureSet(erasureSet); err != nil {
		return nil, err
	}
	return erasureSet, nil
}

// What a file that passed indexValidateFile holds, so its caller need not decode it again: a shard's layout, a slot or
// large entry, or a small file's message.
type indexValidatedFile struct {
	path        indexPath
	shardLayout *indexShardLayout
	slot        *indexSlot
	message     proto.Message
}

// The largest file each path may name: a slot's or erasure set's 16,208 B, and 1 MiB for the rest (D-EVS-48).
func indexPathCap(kind indexPathKind, settings *IndexFormatSettings) int {
	switch kind {
	case indexPathSlot, indexPathErasureSet:
		return settings.SlotMaxByteCount
	}
	return indexShardPaddedMaxByteCount
}

// §11.14's verify row, after 11.9's checks: content_sha256 first, over every frame, so tampered bytes reach no parser;
// then the format of what path names, read whole, and the header's bucket, writer and seq against the path's. A file
// past 1 MiB, a dictionary out of order, a docid out of range, a tombstone table out of order or naming a key its doc
// table holds, a tombstone in an all shard and any non-canonical encoding are refused: the reader drops the file and
// raises index_malformed. A file in a newer format answers errIndexNewerFormat, which reads status update instead.
func indexValidateFile(path indexPath, source indexFrameSource, contentSha256 []byte, settings *IndexFormatSettings) (*indexValidatedFile, error) {
	length := source.indexLength()
	if indexPathCap(path.kind, settings) < length {
		return nil, indexMalformed("a file past its cap")
	}
	cursor := indexNewFrameCursor(source)
	digest := sha256.New()
	chunk := make([]byte, 0, EvsRecordFrameByteCount)
	for position := 0; position < length; position += len(chunk) {
		chunk = chunk[:min(EvsRecordFrameByteCount, length-position)]
		if err := cursor.read(position, chunk); err != nil {
			return nil, err
		}
		digest.Write(chunk)
	}
	if !bytes.Equal(digest.Sum(nil), contentSha256) {
		return nil, indexMalformed("plaintext hash mismatch")
	}
	validated := &indexValidatedFile{path: path}

	switch path.kind {
	case indexPathAllShard, indexPathBucketShard:
		reader, err := indexOpenShard(source, path.companion)
		if err != nil {
			return nil, err
		}
		header := reader.layout.header
		if path.kind == indexPathAllShard && header.Type != indexFileAllShard ||
			path.kind == indexPathBucketShard && (header.Type != indexFileBucketShard || header.BucketStartDay != path.bucketStartDay) {
			return nil, indexMalformed("a shard that is not its path's")
		}
		if err := reader.walk(indexShardVisitor{}); err != nil {
			return nil, err
		}
		validated.shardLayout = reader.layout
		return validated, nil
	}

	file := make([]byte, length)
	if err := cursor.read(0, file); err != nil {
		return nil, err
	}
	var err error
	switch path.kind {
	case indexPathSlot, indexPathLargeEntry:
		slot, err := indexDecodeSlot(file, contentSha256, path.companion, settings)
		if err != nil {
			return nil, err
		}
		header := slot.header
		wantType := uint32(indexFileSlot)
		if path.kind == indexPathLargeEntry {
			wantType = indexFileLargeEntry
		}
		if header.Type != wantType || header.BucketStartDay != path.bucketStartDay ||
			!bytes.Equal(header.WriterSidecarId, path.writerSidecarId[:]) ||
			path.kind == indexPathLargeEntry && header.Seq != path.seq {
			return nil, indexMalformed("a slot that is not its path's")
		}
		validated.slot = slot
	case indexPathSettings:
		validated.message, err = indexDecodeSettings(file)
	case indexPathLock:
		validated.message, err = indexDecodeLock(file)
	case indexPathAllManifest:
		validated.message, err = indexDecodeManifest(file, true)
	case indexPathBucketManifest:
		var manifest *protocol.IndexManifest
		manifest, err = indexDecodeManifest(file, false)
		if err == nil && manifest.StartDay != path.bucketStartDay {
			err = indexMalformed("a manifest that is not its path's bucket")
		}
		validated.message = manifest
	case indexPathErasureSet:
		validated.message, err = indexDecodeErasureSet(file, settings)
	default:
		err = indexMalformed("no index file")
	}
	if err != nil {
		return nil, err
	}
	return validated, nil
}
