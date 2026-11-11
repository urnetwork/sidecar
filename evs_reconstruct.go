// Reconstruction (§11.7's reconstruction row): a verified file version's sealed fields opened, its chain's records read
// and opened, the deltas applied in order to the checkpoint, and the blob's oid and size checked against the sealed
// fields before a byte reaches the caller.
//
// A chain is at most EvsChainMaxRecordCount records (a checkpoint and 16 diffs, PLAN.md:63), or a large file's 4 MiB
// chunk records in order. A segment record is read from two ranges, its segment's header and key block and the
// record itself, opened under fek and manifest of the segment header's generation, which the ladder reaches for a
// moved entry's older generation; a slot-keyed record opens its key from the slot under fek of the key's generation.
// An inline chain's first record opens with its own key block under fek of the push's generation.
//
// Nothing holds a whole file: each record's body and each intermediate result goes to an evsSpill, in memory up to
// EvsSettings.DeltaBaseMemoryByteCount and past it in the sealed local store in 64 KiB chunks, which serve a delta's
// random reads of its base (R-EVS-14, about 1.5 times the file in all). A range evs did not carry in the read's reply
// is fetched in one more round; one evs answers missing on the path's newest version raises evs_alarm
// missing_segment.
//
// On every leg. Not safe for concurrent use: one reconstruction at a time per read.

package sidecar

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

// A diff chain's bound: a checkpoint and N = 16 diffs (§11.7's checkpoint rule (1)).
const EvsChainMaxRecordCount = 17

// v0's file cap (§11.7's large files): the most a reconstruction produces.
const EvsFileMaxByteCount = 2 * 1024 * 1024 * 1024

// The bytes a segment record's open needs ahead of the record: the public header and a general repo's key block.
const evsSegmentKeyedHeaderByteCount = EvsSegmentHeaderByteCount + EvsWrappedKeyByteCount

// The sealed store's spill directory, under the evs component's.
const evsSpillDirectory = "spill/"

// The chunk a spill's sealed files hold: one AEAD unit of the store, read whole for each ReadAt.
const evsSpillChunkByteCount = 64 * 1024

// evs answered a needed object missing.
var ErrEvsObjectMissing = errors.New("evs: object missing")

// Bytes of a known length, in memory up to a bound and past it in the sealed local store, readable at any offset:
// an EvsGitDeltaSource.
type evsSpill struct {
	store       SidecarStore
	memoryLimit int64
	name        string
	memory      []byte
	// the sealed chunks written, in order, and the partial one in memory past them
	chunkCount int
	size       int64
	closed     bool
}

// A spill under store's spill directory, in memory up to memoryLimit.
func newEvsSpill(store SidecarStore, memoryLimit int64) *evsSpill {
	return &evsSpill{store: store, memoryLimit: memoryLimit, name: evsSpillDirectory + hex.EncodeToString(NewEvsSlotId().Bytes())}
}

// Appends p, moving to the sealed store once past the memory bound.
func (self *evsSpill) Write(p []byte) (int, error) {
	if self.closed {
		return 0, io.ErrClosedPipe
	}
	self.memory = append(self.memory, p...)
	self.size += int64(len(p))
	if self.chunkCount == 0 && int64(len(self.memory)) <= self.memoryLimit {
		return len(p), nil
	}
	for evsSpillChunkByteCount <= len(self.memory) {
		if err := self.writeChunk(self.memory[:evsSpillChunkByteCount]); err != nil {
			return 0, err
		}
		self.memory = append([]byte{}, self.memory[evsSpillChunkByteCount:]...)
	}
	return len(p), nil
}

// One sealed chunk file.
func (self *evsSpill) writeChunk(chunk []byte) error {
	writer, err := self.store.Create(fmt.Sprintf("%s/%08d", self.name, self.chunkCount))
	if err != nil {
		return err
	}
	defer writer.Close()
	if _, err := writer.Write(chunk); err != nil {
		return err
	}
	if err := writer.Commit(); err != nil {
		return err
	}
	self.chunkCount += 1
	return nil
}

// The bytes written.
func (self *evsSpill) Size() int64 {
	return self.size
}

// Reads at off: memory, or the sealed chunks and the memory tail past them.
func (self *evsSpill) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || self.size < off {
		return 0, io.EOF
	}
	read := 0
	for read < len(p) && off+int64(read) < self.size {
		at := off + int64(read)
		var source []byte
		var sourceAt int64
		chunkBytes := int64(self.chunkCount) * evsSpillChunkByteCount
		if at < chunkBytes {
			chunk, err := self.readChunk(int(at / evsSpillChunkByteCount))
			if err != nil {
				return read, err
			}
			source = chunk
			sourceAt = at % evsSpillChunkByteCount
		} else {
			source = self.memory
			sourceAt = at - chunkBytes
		}
		read += copy(p[read:], source[sourceAt:])
	}
	if read < len(p) {
		return read, io.EOF
	}
	return read, nil
}

// One sealed chunk's bytes, authenticated as it is read.
func (self *evsSpill) readChunk(index int) ([]byte, error) {
	reader, err := self.store.Open(fmt.Sprintf("%s/%08d", self.name, index))
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}

// A reader of the whole spill from the start.
func (self *evsSpill) reader() io.Reader {
	return io.NewSectionReader(self, 0, self.size)
}

// Drops the spill's sealed chunks.
func (self *evsSpill) close() {
	if self.closed {
		return
	}
	self.closed = true
	self.memory = nil
	for index := 0; index < self.chunkCount; index += 1 {
		self.store.Remove(fmt.Sprintf("%s/%08d", self.name, index))
	}
}

// One object range a reply carried, by kind, id and the offset it starts at.
type evsReadObjectKey struct {
	kind   protocol.EvsReadObjectKind
	id     string
	number uint64
	offset uint32
}

// The objects a read's replies carried, each in its spill.
type evsReadObjects struct {
	client  *EvsClient
	objects map[evsReadObjectKey]*evsSpill
	missing map[string]bool
	// the object a continued frame extends
	last    evsReadObjectKey
	lastEnd int64
}

// An empty set of a read's objects.
func newEvsReadObjects(client *EvsClient) *evsReadObjects {
	return &evsReadObjects{client: client, objects: map[evsReadObjectKey]*evsSpill{}, missing: map[string]bool{}}
}

// Takes one object frame: a new range, the next slice of the last one, or a missing object.
func (self *evsReadObjects) add(object *protocol.EvsReadObject) error {
	id := hex.EncodeToString(object.GetId())
	if object.GetMissing() {
		self.missing[id] = true
		return nil
	}
	key := evsReadObjectKey{kind: object.GetKind(), id: id, number: object.GetNumber(), offset: object.GetOffset()}
	if spill, ok := self.objects[self.last]; ok && self.last.kind == key.kind && self.last.id == key.id &&
		self.last.number == key.number && int64(object.GetOffset()) == self.lastEnd {
		if _, err := spill.Write(object.GetBody()); err != nil {
			return err
		}
		self.lastEnd += int64(len(object.GetBody()))
		return nil
	}
	spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
	if _, err := spill.Write(object.GetBody()); err != nil {
		return err
	}
	if held := self.objects[key]; held != nil {
		held.close()
	}
	self.objects[key] = spill
	self.last = key
	self.lastEnd = int64(object.GetOffset()) + int64(len(object.GetBody()))
	return nil
}

// The bytes [offset, offset+length) of a segment, from a range a reply carried that holds them.
func (self *evsReadObjects) segmentRange(segmentId []byte, offset uint32, length uint32) (io.Reader, bool) {
	id := hex.EncodeToString(segmentId)
	for key, spill := range self.objects {
		if key.kind != protocol.EvsReadObjectKind_EVS_READ_OBJECT_SEGMENT || key.id != id {
			continue
		}
		if key.offset <= offset && int64(offset)+int64(length) <= int64(key.offset)+spill.Size() {
			return io.NewSectionReader(spill, int64(offset-key.offset), int64(length)), true
		}
	}
	return nil, false
}

// A slot's object bytes, when a reply carried them.
func (self *evsReadObjects) slot(slotId []byte) ([]byte, bool) {
	spill, ok := self.objects[evsReadObjectKey{kind: protocol.EvsReadObjectKind_EVS_READ_OBJECT_SLOT, id: hex.EncodeToString(slotId)}]
	if !ok {
		return nil, false
	}
	slotBytes, err := io.ReadAll(spill.reader())
	return slotBytes, err == nil
}

// Drops every spill.
func (self *evsReadObjects) close() {
	if self == nil {
		return
	}
	for _, spill := range self.objects {
		spill.close()
	}
	self.objects = map[evsReadObjectKey]*evsSpill{}
}

// Fetches the ranges and slots a version's chain needs that the reply did not carry, in one more round.
func (self *EvsRepo) fetchMissing(ctx context.Context, result *evsReadResult, entry *protocol.EvsEntryVersion) error {
	ranges := []*protocol.EvsReadRange{}
	for _, locator := range entry.GetChain() {
		if protocol.EvsLocatorKind(locator.GetKind()) != protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT {
			continue
		}
		if _, ok := result.objects.segmentRange(locator.GetId(), 0, evsSegmentKeyedHeaderByteCount); !ok {
			ranges = append(ranges, &protocol.EvsReadRange{SegmentId: locator.GetId(), Offset: 0, Length: evsSegmentKeyedHeaderByteCount})
		}
		if _, ok := result.objects.segmentRange(locator.GetId(), locator.GetOffset(), locator.GetLength()); !ok {
			ranges = append(ranges, &protocol.EvsReadRange{SegmentId: locator.GetId(), Offset: locator.GetOffset(), Length: locator.GetLength()})
		}
	}
	slotIds := [][]byte{}
	for _, slotId := range entry.GetSlotIds() {
		if _, ok := result.objects.slot(slotId); !ok {
			slotIds = append(slotIds, slotId)
		}
	}
	// a round takes at most 64 ranges of at most 32 MiB in all (§11.9's request row), so a file past that, a chunked
	// one of up to 2 GiB, fetches in rounds; the slots go with the first
	requests := []*protocol.EvsReadRequest{}
	var request *protocol.EvsReadRequest
	requestByteCount := uint64(0)
	for _, readRange := range ranges {
		if request == nil || EvsReadMaxRangeCount <= len(request.Ranges) || EvsReadMaxRangeByteCount < requestByteCount+uint64(readRange.GetLength()) {
			request = &protocol.EvsReadRequest{RefId: result.refId.Bytes(), PinVersion: result.head.Version}
			requests = append(requests, request)
			requestByteCount = 0
		}
		request.Ranges = append(request.Ranges, readRange)
		requestByteCount += uint64(readRange.GetLength())
	}
	if 0 < len(slotIds) {
		if len(requests) == 0 {
			requests = append(requests, &protocol.EvsReadRequest{RefId: result.refId.Bytes(), PinVersion: result.head.Version})
		}
		requests[0].SlotIds = slotIds
	}
	for _, request := range requests {
		_, objects, err := self.client.postRead(ctx, self.repoId, request)
		if err != nil {
			return err
		}
		for key, spill := range objects.objects {
			if held := result.objects.objects[key]; held != nil {
				held.close()
			}
			result.objects.objects[key] = spill
		}
		for id := range objects.missing {
			result.objects.missing[id] = true
		}
	}
	return nil
}

// §11.9's request row: one read names at most 64 ranges, of at most 32 MiB in all.
const (
	EvsReadMaxRangeCount     = 64
	EvsReadMaxRangeByteCount = 32 * 1024 * 1024
)

// Rebuilds a verified file version into out, after the receipt gate and with its oid and size checked first.
func (self *EvsRepo) reconstruct(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath, out io.Writer) (*EvsFileInfo, error) {
	info := evsFileInfoOf(result.refId, result.head, verified)
	content, fields, oid, err := self.reconstructContent(ctx, result, verified, nil)
	if err != nil {
		return nil, err
	}
	defer content.close()
	if _, err := io.Copy(out, content.reader()); err != nil {
		return nil, err
	}
	info.Mode = fields.GetMode()
	info.GitOid = oid
	info.Size = fields.GetSize()
	return info, nil
}

// A verified file version's content in a spill the caller closes, after the receipt gate, its size and oid checked
// against its sealed fields, which it gives with the oid. onRecord, when set, sees each record's opened header and
// locator in chain order, which the write planner reads the chain's facts from.
func (self *EvsRepo) reconstructContent(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath, onRecord func(header *EvsRecordHeader, locator *protocol.EvsLocator)) (*evsSpill, *protocol.EvsSealedFields, EvsGitOid, error) {
	entry := verified.Entry
	push := verified.Statement.Push
	chain := entry.GetChain()
	if len(chain) == 0 {
		// a gitlink's, mode 160000, size 0 and the link's oid, and no other file's (DESIGN-DETAILS 8.2.2's gitlink row)
		return self.gitlinkContent(ctx, result, verified)
	}
	objectIds := [][]byte{}
	for _, locator := range chain {
		if len(locator.GetId()) != 0 {
			objectIds = append(objectIds, locator.GetId())
		}
	}
	objectIds = append(objectIds, entry.GetSlotIds()...)
	if err := self.client.preDecrypt(ctx, self.repoId, result.refId, objectIds); err != nil {
		return nil, nil, EvsGitOid{}, err
	}
	keys := result.keys
	manifest, err := keys.manifest(ctx, push.GetGeneration())
	if err != nil {
		return nil, nil, EvsGitOid{}, err
	}
	fields, err := EvsOpenFields(manifest, entry.GetSealedFields())
	if err != nil {
		self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
		return nil, nil, EvsGitOid{}, err
	}
	fileId, err := IdFromBytes(fields.GetFileId())
	if err != nil {
		return nil, nil, EvsGitOid{}, fmt.Errorf("%w: a file id", ErrEvsSealInvalid)
	}
	if fields.GetMode() == EvsGitModeGitlink {
		// a gitlink has no content, so a chain under one is tampering
		self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
		return nil, nil, EvsGitOid{}, fmt.Errorf("%w: a gitlink with a chain", ErrEvsSealInvalid)
	}
	if err := self.fetchMissing(ctx, result, entry); err != nil {
		return nil, nil, EvsGitOid{}, err
	}
	content, err := self.applyChain(ctx, result, push, entry, fileId, onRecord)
	if err != nil {
		var missing bool
		missing = errors.Is(err, ErrEvsObjectMissing)
		if missing {
			self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmMissingSegment, "", nil)
		} else if errors.Is(err, ErrEvsSealInvalid) {
			self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
		}
		return nil, nil, EvsGitOid{}, err
	}
	if uint64(content.Size()) != fields.GetSize() {
		content.close()
		self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
		return nil, nil, EvsGitOid{}, fmt.Errorf("%w: content of %d bytes where its fields say %d", ErrEvsSealInvalid, content.Size(), fields.GetSize())
	}
	oid, err := EvsGitBlobOid(content.reader(), content.Size())
	if err != nil {
		content.close()
		return nil, nil, EvsGitOid{}, err
	}
	if fields.GetOidKind() != protocol.EvsOidKind_EVS_OID_SHA1 || !bytes.Equal(oid[:], fields.GetGitOid()) {
		content.close()
		self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
		return nil, nil, EvsGitOid{}, fmt.Errorf("%w: content whose oid is not its fields'", ErrEvsSealInvalid)
	}
	return content, fields, oid, nil
}

// A file version with an empty chain: a gitlink, its sealed mode 160000, size 0 and the linked commit's oid, which it
// gives as its content's oid over an empty spill. Any other mode, or a size, under an empty chain is tampering, which
// evs cannot see (DESIGN-DETAILS 8.2.2's gitlink row).
func (self *EvsRepo) gitlinkContent(ctx context.Context, result *evsReadResult, verified *EvsVerifiedPath) (*evsSpill, *protocol.EvsSealedFields, EvsGitOid, error) {
	manifest, err := result.keys.manifest(ctx, verified.Statement.Push.GetGeneration())
	if err != nil {
		return nil, nil, EvsGitOid{}, err
	}
	fields, err := EvsOpenFields(manifest, verified.Entry.GetSealedFields())
	if err != nil {
		self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
		return nil, nil, EvsGitOid{}, err
	}
	if fields.GetMode() != EvsGitModeGitlink || fields.GetSize() != 0 {
		self.client.alarm(self.repoId, result.refId, SidecarEvsAlarmTamper, "", nil)
		return nil, nil, EvsGitOid{}, fmt.Errorf("%w: an empty chain under mode %o", ErrEvsSealInvalid, fields.GetMode())
	}
	// EvsOpenFields held the oid to SHA-1's 20 bytes
	oid := EvsGitOid(fields.GetGitOid())
	return newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount), fields, oid, nil
}

// Runs a chain into a spill: a checkpoint then each diff on the result before it, or chunks one after another.
func (self *EvsRepo) applyChain(ctx context.Context, result *evsReadResult, push *protocol.EvsPush, entry *protocol.EvsEntryVersion, fileId Id, onRecord func(header *EvsRecordHeader, locator *protocol.EvsLocator)) (*evsSpill, error) {
	store := self.client.args.Store
	memoryLimit := self.client.settings.DeltaBaseMemoryByteCount
	var current *evsSpill
	closeCurrent := func() {
		if current != nil {
			current.close()
		}
	}
	var inlineKey *EvsObjectKey
	var previousRecordId Id
	diffCount := 0
	for index, locator := range entry.GetChain() {
		header, body, nextInlineKey, err := self.openRecord(ctx, result, push, entry, fileId, locator, index == 0, inlineKey)
		if err != nil {
			closeCurrent()
			return nil, err
		}
		inlineKey = nextInlineKey
		if onRecord != nil {
			onRecord(header, locator)
		}
		switch header.Kind {
		case protocol.EvsRecordKind_EVS_RECORD_CHECKPOINT:
			if index != 0 {
				closeCurrent()
				return nil, fmt.Errorf("%w: a checkpoint inside a chain", ErrEvsSealInvalid)
			}
			current = newEvsSpill(store, memoryLimit)
			if _, err := io.Copy(current, body); err != nil {
				closeCurrent()
				return nil, err
			}
		case protocol.EvsRecordKind_EVS_RECORD_DIFF:
			diffCount += 1
			if current == nil || header.BaseRecordId != previousRecordId || EvsChainMaxRecordCount <= diffCount {
				closeCurrent()
				return nil, fmt.Errorf("%w: a diff off its chain", ErrEvsSealInvalid)
			}
			next := newEvsSpill(store, memoryLimit)
			if _, err := EvsGitDeltaApply(current, body, EvsFileMaxByteCount, next, DefaultEvsGitDeltaSettings()); err != nil {
				next.close()
				closeCurrent()
				return nil, fmt.Errorf("%w: %w", ErrEvsSealInvalid, err)
			}
			current.close()
			current = next
		case protocol.EvsRecordKind_EVS_RECORD_CHUNK:
			if current == nil {
				if index != 0 {
					return nil, fmt.Errorf("%w: a chunk after a checkpoint", ErrEvsSealInvalid)
				}
				current = newEvsSpill(store, memoryLimit)
			}
			if _, err := io.Copy(current, body); err != nil {
				closeCurrent()
				return nil, err
			}
		}
		previousRecordId = header.RecordId
	}
	return current, nil
}

// One record of a chain, its header opened and its body's reader: inline, from its locator's bytes; in a segment,
// from the segment's key block and the record's range.
func (self *EvsRepo) openRecord(ctx context.Context, result *evsReadResult, push *protocol.EvsPush, entry *protocol.EvsEntryVersion, fileId Id, locator *protocol.EvsLocator, first bool, inlineKey *EvsObjectKey) (*EvsRecordHeader, io.Reader, *EvsObjectKey, error) {
	keys := result.keys
	switch protocol.EvsLocatorKind(locator.GetKind()) {
	case protocol.EvsLocatorKind_EVS_LOCATOR_INLINE:
		manifest, err := keys.manifest(ctx, push.GetGeneration())
		if err != nil {
			return nil, nil, nil, err
		}
		var fekKey *EvsFekKey
		if first || inlineKey == nil {
			fekKey, err = keys.fek(ctx, push.GetGeneration())
			if err != nil {
				return nil, nil, nil, err
			}
			inlineKey = nil
		}
		header, body, objectKey, err := EvsOpenInlineRecord(manifest, fekKey, inlineKey, fileId, locator.GetInline())
		if err != nil {
			return nil, nil, nil, err
		}
		return header, bytes.NewReader(body), objectKey, nil
	case protocol.EvsLocatorKind_EVS_LOCATOR_SEGMENT:
		if result.objects.missing[hex.EncodeToString(locator.GetId())] {
			return nil, nil, nil, ErrEvsObjectMissing
		}
		headerRange, ok := result.objects.segmentRange(locator.GetId(), 0, evsSegmentKeyedHeaderByteCount)
		if !ok {
			return nil, nil, nil, ErrEvsObjectMissing
		}
		recordRange, ok := result.objects.segmentRange(locator.GetId(), locator.GetOffset(), locator.GetLength())
		if !ok {
			return nil, nil, nil, ErrEvsObjectMissing
		}
		headerBytes, err := io.ReadAll(headerRange)
		if err != nil {
			return nil, nil, nil, err
		}
		segmentHeader, err := ParseEvsSegmentHeader(headerBytes)
		if err != nil {
			return nil, nil, nil, err
		}
		if segmentHeader.RepoId != self.repoId {
			return nil, nil, nil, fmt.Errorf("%w: a segment of another repo", ErrEvsSealInvalid)
		}
		manifest, err := keys.manifest(ctx, segmentHeader.Generation)
		if err != nil {
			return nil, nil, nil, err
		}
		sealedHeader := make([]byte, EvsRecordHeaderByteCount)
		if _, err := io.ReadFull(recordRange, sealedHeader); err != nil {
			return nil, nil, nil, fmt.Errorf("%w: a record range cut short", ErrEvsSealInvalid)
		}
		header, err := EvsOpenRecordHeader(manifest, sealedHeader)
		if err != nil {
			return nil, nil, nil, err
		}
		if EvsRecordByteCount(header.BodyLength) != uint64(locator.GetLength()) {
			return nil, nil, nil, fmt.Errorf("%w: a record whose length is not its locator's", ErrEvsSealInvalid)
		}
		var objectKey *EvsObjectKey
		switch header.KeyRefKind {
		case protocol.EvsKeyRefKind_EVS_KEY_REF_CONTAINER:
			if header.Generation != segmentHeader.Generation {
				return nil, nil, nil, fmt.Errorf("%w: a container-keyed record of another generation", ErrEvsSealInvalid)
			}
			fekKey, err := keys.fek(ctx, segmentHeader.Generation)
			if err != nil {
				return nil, nil, nil, err
			}
			objectKey, err = EvsUnwrapObjectKey(fekKey, headerBytes[EvsSegmentHeaderByteCount:evsSegmentKeyedHeaderByteCount])
			if err != nil {
				return nil, nil, nil, err
			}
		default:
			objectKey, err = self.slotKey(ctx, result, header)
			if err != nil {
				return nil, nil, nil, err
			}
		}
		reader := NewEvsRecordReader()
		if err := reader.Begin(recordRange, header, objectKey, self.repoId, fileId); err != nil {
			return nil, nil, nil, err
		}
		return header, reader, inlineKey, nil
	default:
		return nil, nil, nil, fmt.Errorf("%w: locator kind %d", ErrEvsFormatUnsupported, locator.GetKind())
	}
}

// The key a slot-keyed record names, from its slot under fek of the key's generation; a deposit's, opened by the drop
// key before the read reconstructs it (evs_consume.go).
func (self *EvsRepo) slotKey(ctx context.Context, result *evsReadResult, header *EvsRecordHeader) (*EvsObjectKey, error) {
	if deposit := result.keys.deposit; deposit != nil && deposit.slotId == header.SlotId {
		if header.KeyIndex != 0 || header.Generation != deposit.generation {
			return nil, fmt.Errorf("%w: a deposit record naming another key", ErrEvsSealInvalid)
		}
		return deposit.objectKey, nil
	}
	slotBytes, ok := result.objects.slot(header.SlotId.Bytes())
	if !ok {
		return nil, ErrEvsObjectMissing
	}
	slot, err := EvsDecodeSlotObject(slotBytes)
	if err != nil {
		return nil, err
	}
	slotKey, ok := EvsSlotKeyAt(slot, uint32(header.KeyIndex))
	if !ok || slotKey.GetGeneration() != header.Generation {
		return nil, fmt.Errorf("%w: a slot without the record's key", ErrEvsSealInvalid)
	}
	fekKey, err := result.keys.fek(ctx, slotKey.GetGeneration())
	if err != nil {
		return nil, err
	}
	return EvsOpenSlotKey(fekKey, slotKey)
}

// A time_ms as a time.
func evsTime(timeMs int64) time.Time {
	return time.UnixMilli(timeMs).UTC()
}
