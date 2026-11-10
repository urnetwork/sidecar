// Batches and records in format 2 (§11.8's batches, EVS-FORMAT.md's format 2 chapter). A format-2 record is one that
// stages segments or lists purge candidates: its header's byte 1, which format 1 writes zero, is 2, and its body is
// format 1's items followed by two more, its staged bytes (evs_staged.go; empty when none) and its EvsPurgeList's
// deterministic bytes (empty when none). Any other record keeps format 1's form, in a batch of either format, and a
// batch's header format is 2 exactly when it holds a format-2 record. So a record read alone at its place shows its own
// format, and a place's offsets never move when a later record turns its batch to format 2.
//
// A seal or reseed record stages nothing. A record's bounds count its tail (plan-EVS2-small-readings#13). Format-1
// readers refuse a format-2 batch and a format-2 record as FORMAT_UNSUPPORTED; format-2 readers take both formats, and
// an evacuator meeting a format it does not know leaves the batch, alarming.
//
// On every leg. Package-level functions are safe for concurrent use; an EvsBatchWriter is not.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// Format 2's record layout and the purge list's bound (EVS-FORMAT.md).
const (
	// the record header's byte that says its format: 0 format 1's form, 2 a format-2 record with its tail
	evsBatchRecordFormatByte = 1
	evsBatchRecordFormat2    = 2
	// the items a format-2 record's body ends with: its staged bytes and its purge list
	evsBatchRecordTailItemCount = 2
	// §11.13's purge row: past this many ids, a purge list is marked instead
	EvsPurgeListMaxIdCount = 2048
)

// A format-2 record's tail: what rides after its format-1 items.
type EvsBatchRecordTail struct {
	// the staged bytes, as EvsEncodeStaged frames them; nil when none
	Staged []byte
	// the EvsPurgeList's deterministic bytes; nil when none
	PurgeList []byte
}

// Whether there is nothing to carry, so the record keeps format 1's form.
func (self *EvsBatchRecordTail) Empty() bool {
	return self == nil || (len(self.Staged) == 0 && len(self.PurgeList) == 0)
}

// The staged segments, each bounded, as EvsDecodeStaged reads them.
func (self *EvsBatchRecordTail) StagedSegments() ([][]byte, error) {
	return EvsDecodeStaged(self.Staged)
}

// The purge list, held to its shape, or nil when the record lists none.
func (self *EvsBatchRecordTail) PurgeListValue() (*protocol.EvsPurgeList, error) {
	if len(self.PurgeList) == 0 {
		return nil, nil
	}
	return DecodeEvsPurgeList(self.PurgeList)
}

// A purge list's deterministic bytes, held to its shape first.
func EncodeEvsPurgeList(list *protocol.EvsPurgeList) ([]byte, error) {
	if err := checkEvsPurgeList(list); err != nil {
		return nil, err
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(list)
	if err != nil {
		return nil, fmt.Errorf("evs: purge list: %w", err)
	}
	return encoded, nil
}

// A purge list's bytes held to its shape (checkEvsPurgeList).
func DecodeEvsPurgeList(listBytes []byte) (*protocol.EvsPurgeList, error) {
	list := &protocol.EvsPurgeList{}
	if err := proto.Unmarshal(listBytes, list); err != nil {
		return nil, fmt.Errorf("%w: a purge list that does not parse", ErrEvsPushInvalid)
	}
	if err := checkEvsPurgeList(list); err != nil {
		return nil, err
	}
	return list, nil
}

// §11.13's purge row as a shape: marked with no candidate, or one or more candidates, each a path of 1 to 32
// components, a replaced version, and at least one id, segment ids 32 B and slot ids 16 B, unrepeated; 2,048 ids
// at most in all.
func checkEvsPurgeList(list *protocol.EvsPurgeList) error {
	if list.GetMarked() {
		if len(list.GetCandidates()) != 0 {
			return fmt.Errorf("%w: a marked purge list listing candidates", ErrEvsPushInvalid)
		}
		return nil
	}
	if len(list.GetCandidates()) == 0 {
		return fmt.Errorf("%w: a purge list of nothing", ErrEvsPushInvalid)
	}
	idCount := 0
	for _, candidate := range list.GetCandidates() {
		if _, err := ParseEvsChangedTokenPath(candidate.GetTokenPath()); err != nil {
			return fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
		}
		if candidate.GetReplacedVersion() == 0 {
			return fmt.Errorf("%w: a candidate of no version", ErrEvsPushInvalid)
		}
		ids := map[string]bool{}
		for _, group := range []struct {
			ids    [][]byte
			length int
		}{
			{ids: candidate.GetSegmentIds(), length: sha256.Size},
			{ids: candidate.GetStagedSegmentIds(), length: sha256.Size},
			{ids: candidate.GetSlotIds(), length: 16},
		} {
			for _, id := range group.ids {
				if len(id) != group.length || ids[string(id)] {
					return fmt.Errorf("%w: a candidate id of %d bytes, or one repeated", ErrEvsPushInvalid, len(id))
				}
				ids[string(id)] = true
			}
		}
		if len(ids) == 0 {
			return fmt.Errorf("%w: a candidate of no id", ErrEvsPushInvalid)
		}
		idCount += len(ids)
	}
	if EvsPurgeListMaxIdCount < idCount {
		return fmt.Errorf("%w: a purge list of %d ids, which must be marked", ErrEvsPushInvalid, idCount)
	}
	return nil
}

// The record's bytes with its tail: byte 1 set to 2, and the staged and purge-list items after its body.
func (self *EvsBatchRecord) encodeFormat2(tail *EvsBatchRecordTail) []byte {
	withTail := &EvsBatchRecord{
		Type: self.Type, RepoId: self.RepoId, RefId: self.RefId, PushId: self.PushId,
		SignerSidecarId: self.SignerSidecarId, TimeMs: self.TimeMs,
		Body: append(bytes.Clone(self.Body), evsJoinItems([][]byte{tail.Staged, tail.PurgeList})...),
	}
	encoded := withTail.encode()
	encoded[evsBatchRecordFormatByte] = evsBatchRecordFormat2
	return encoded
}

// The record's bytes as a pack or parcel keeps them (§11.13's staged row: packs and parcels never hold staged bytes):
// its purge list kept, which a hold's end and purge's turn-on read back (EVSB-M10-02), its staged item emptied, and
// format 1's form when no purge list is left. Its hashes do not change, since staged bytes ride outside every hash.
func EvsBatchRecordBytesWithoutStaged(record *EvsBatchRecord, tail *EvsBatchRecordTail) []byte {
	if tail == nil || len(tail.PurgeList) == 0 {
		return record.encode()
	}
	return record.encodeFormat2(&EvsBatchRecordTail{PurgeList: tail.PurgeList})
}

// Adds a record of either format and gives its place: with a non-empty tail, a format-2 record, which turns the batch
// to format 2; else format 1's form, as Add writes it. A seal or reseed record stages nothing, and every bound
// counts the tail.
func (self *EvsBatchWriter) AddFormat2(record *EvsBatchRecord, tail *EvsBatchRecordTail) (*protocol.EvsPlace, error) {
	if tail.Empty() {
		return self.Add(record)
	}
	if record.Type < protocol.EvsBatchRecordType_EVS_BATCH_PUSH || protocol.EvsBatchRecordType_EVS_BATCH_RESEED < record.Type {
		return nil, fmt.Errorf("%w: record type %d", ErrEvsPushInvalid, record.Type)
	}
	if len(tail.Staged) != 0 && (record.Type == protocol.EvsBatchRecordType_EVS_BATCH_SEAL || record.Type == protocol.EvsBatchRecordType_EVS_BATCH_RESEED) {
		return nil, fmt.Errorf("%w: a seal or reseed record staging segments", ErrEvsPushInvalid)
	}
	if _, err := tail.StagedSegments(); err != nil {
		return nil, err
	}
	if _, err := tail.PurgeListValue(); err != nil {
		return nil, err
	}
	encoded := record.encodeFormat2(tail)
	if !self.Fits(len(encoded) - EvsBatchRecordHeaderByteCount) {
		return nil, fmt.Errorf("%w: a record of %d bytes with its tail past the batch's bound", ErrEvsPushInvalid, len(encoded))
	}
	offset := uint32(EvsBatchHeaderByteCount + len(self.records))
	self.records = append(self.records, encoded...)
	self.index = binary.BigEndian.AppendUint32(self.index, offset)
	self.index = binary.BigEndian.AppendUint32(self.index, uint32(len(encoded)))
	self.count += 1
	self.header.Format = evsBatchFormat2
	return &protocol.EvsPlace{
		Minute: self.header.Minute, Instance: self.header.Instance, Seq: self.header.Seq,
		Offset: offset, Length: uint32(len(encoded)),
	}, nil
}

// A record of either format from exactly its bytes, as a read at its place gets them: format 1's form, its tail nil,
// or a format-2 record, whose body ends with its staged and purge-list items, the tail split off and held to its
// shape, a tail carrying nothing refused, since such a record keeps format 1's form.
func ParseEvsBatchRecordFormat2(recordBytes []byte) (*EvsBatchRecord, *EvsBatchRecordTail, error) {
	return parseEvsBatchRecord(recordBytes, true)
}

// A format-2 record's tail, split off the end of its body's items: the body without it, and the tail held to its
// shape, a seal or reseed staging nothing.
func splitEvsBatchRecordTail(recordType protocol.EvsBatchRecordType, body []byte) ([]byte, *EvsBatchRecordTail, error) {
	starts := []int{}
	for at := 0; at < len(body); {
		if len(body)-at < 4 {
			return nil, nil, fmt.Errorf("%w: a record item's length cut short", ErrEvsPushInvalid)
		}
		starts = append(starts, at)
		length := int(binary.BigEndian.Uint32(body[at : at+4]))
		if len(body)-at-4 < length {
			return nil, nil, fmt.Errorf("%w: a record item past its body", ErrEvsPushInvalid)
		}
		at += 4 + length
	}
	if len(starts) <= evsBatchRecordTailItemCount {
		return nil, nil, fmt.Errorf("%w: a format-2 record of %d items", ErrEvsPushInvalid, len(starts))
	}
	tailAt := starts[len(starts)-evsBatchRecordTailItemCount]
	items, err := EvsPayloadItems(body[tailAt:])
	if err != nil {
		return nil, nil, err
	}
	tail := &EvsBatchRecordTail{}
	if 0 < len(items[0]) {
		tail.Staged = items[0]
	}
	if 0 < len(items[1]) {
		tail.PurgeList = items[1]
	}
	if tail.Empty() {
		return nil, nil, fmt.Errorf("%w: a format-2 record carrying no tail", ErrEvsPushInvalid)
	}
	if len(tail.Staged) != 0 && (recordType == protocol.EvsBatchRecordType_EVS_BATCH_SEAL || recordType == protocol.EvsBatchRecordType_EVS_BATCH_RESEED) {
		return nil, nil, fmt.Errorf("%w: a seal or reseed record staging segments", ErrEvsPushInvalid)
	}
	if _, err := tail.StagedSegments(); err != nil {
		return nil, nil, err
	}
	if _, err := tail.PurgeListValue(); err != nil {
		return nil, nil, err
	}
	return body[:tailAt], tail, nil
}

// A batch of either format read whole and checked as ParseEvsBatch checks one, each record of either form, and each
// format-2 record's tail beside it in Tails (nil for format 1's form). A batch of format 2 holds a format-2 record and
// one of format 1 none; a format past 2 is ErrEvsFormatUnsupported, which an evacuator leaves, alarming.
func ParseEvsBatchFormat2(batchBytes []byte) (*EvsBatch, error) {
	return parseEvsBatch(batchBytes, true)
}

// The record at place, of either format, with its tail when it is a format-2 record.
func (self *EvsBatchReader) RecordFormat2(place *protocol.EvsPlace) (*EvsBatchRecord, *EvsBatchRecordTail, error) {
	if place.GetOffset() < EvsBatchHeaderByteCount || place.GetLength() < EvsBatchRecordHeaderByteCount ||
		EvsBatchMaxRecordByteCount < place.GetLength() {
		return nil, nil, fmt.Errorf("%w: a place no record has", ErrEvsPushInvalid)
	}
	recordBytes := make([]byte, place.GetLength())
	if _, err := self.in.ReadAt(recordBytes, int64(place.GetOffset())); err != nil {
		return nil, nil, err
	}
	return ParseEvsBatchRecordFormat2(recordBytes)
}
