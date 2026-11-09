// Batches (§11.8's batches, D-EVS-30): each evs process group-commits push, part, seal and reseed records into
// immutable minute-bucketed objects of at most 256 KiB, or one record of up to 1 MiB, at
// pb/<yyyymmddhh>/<mm>/<instance>-<seq>, evacuated whole after 25-26 h. A batch is header | records | index | trailer
// (plan-EVS1-format-bytes#7), integers big-endian:
//
//	header, 32 B   "URpb" | format u8 | 3 zero bytes | instance u32 | minute u32 | seq u32 | created_ms i64 |
//	               record_count u32
//	record         type u8 | 3 zero bytes | repo_id 16 | ref_id 16 | push_id 16 | signer_sidecar_id 16 | time_ms i64 |
//	               length u32 | body
//	index          offset u32 | length u32 per record, in record order
//	trailer, 36 B  index_offset u32 | SHA-256 of every byte before the trailer
//
// A record's body is its items in §11.8's record row's order, each u32 length | bytes (EVS-FORMAT.md): a push's
// Signed EvsPush and payload; a part's Signed EvsPush, EvsPushPart, one item per receipt and the head version it was
// checked at as a u64 item; a seal's Signed EvsPush and one item per part of its 20 B place, 32 B changes_root and
// first token path; a reseed's re-seeded Signed EvsPush and payload. A record is committed only at the place its
// window entry names, so a second copy of it is dead weight.
//
// Format 1 writes format 1. A batch of format 2, which holds staged segments or purge candidates, is refused as
// ErrEvsFormatUnsupported, so an evacuator that does not know it leaves it with an alarm, and so is a format-2 record,
// whose header's byte 1 is 2; anything else unknown is ErrEvsPushInvalid. evs_batch_format2.go writes and reads
// format 2's records and batches through the same parse.
//
// On every leg. Package-level functions are safe for concurrent use; an EvsBatchWriter is not.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.8's batch layout and bounds.
const (
	EvsBatchHeaderByteCount       = 32
	EvsBatchRecordHeaderByteCount = 80
	EvsBatchTrailerByteCount      = 4 + sha256.Size
	// a batch of several records
	EvsBatchMaxByteCount = 256 * 1024
	// a record alone in its batch
	EvsBatchMaxRecordByteCount = 1024 * 1024

	evsBatchMagic                    = "URpb"
	evsBatchFormat1             byte = 1
	evsBatchFormat2             byte = 2
	evsBatchIndexEntryByteCount      = 8
)

// A batch's header.
type EvsBatchHeader struct {
	Format uint8
	// the writing process's random 32-bit id
	Instance uint32
	// minutes since the Unix epoch, UTC, when the batch opened
	Minute    uint32
	Seq       uint32
	CreatedMs int64
}

// One batch record: who wrote what for which ref, and its body's items.
type EvsBatchRecord struct {
	Type            protocol.EvsBatchRecordType
	RepoId          Id
	RefId           Id
	PushId          Id
	SignerSidecarId Id
	TimeMs          int64
	Body            []byte
}

// The record's bytes: its 80 B header, then its body.
func (self *EvsBatchRecord) encode() []byte {
	encoded := make([]byte, 0, EvsBatchRecordHeaderByteCount+len(self.Body))
	encoded = append(encoded, byte(self.Type), 0, 0, 0)
	encoded = append(encoded, self.RepoId[:]...)
	encoded = append(encoded, self.RefId[:]...)
	encoded = append(encoded, self.PushId[:]...)
	encoded = append(encoded, self.SignerSidecarId[:]...)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(self.TimeMs))
	encoded = binary.BigEndian.AppendUint32(encoded, uint32(len(self.Body)))
	return append(encoded, self.Body...)
}

// A record from exactly its bytes, as a read at its place gets them: a type format 1 has, its zero bytes zero, and a
// length that is the rest. A format-2 record is ErrEvsFormatUnsupported.
func ParseEvsBatchRecord(recordBytes []byte) (*EvsBatchRecord, error) {
	record, _, err := parseEvsBatchRecord(recordBytes, false)
	return record, err
}

// A record as ParseEvsBatchRecord reads it, and with format2 a format-2 record too, whose tail is split off its body
// (evs_batch_format2.go).
func parseEvsBatchRecord(recordBytes []byte, format2 bool) (*EvsBatchRecord, *EvsBatchRecordTail, error) {
	if len(recordBytes) < EvsBatchRecordHeaderByteCount {
		return nil, nil, fmt.Errorf("%w: a record of %d bytes", ErrEvsPushInvalid, len(recordBytes))
	}
	recordType := protocol.EvsBatchRecordType(recordBytes[0])
	if recordType < protocol.EvsBatchRecordType_EVS_BATCH_PUSH || protocol.EvsBatchRecordType_EVS_BATCH_RESEED < recordType {
		return nil, nil, fmt.Errorf("%w: record type %d", ErrEvsPushInvalid, recordType)
	}
	recordFormat := recordBytes[evsBatchRecordFormatByte]
	if recordFormat == evsBatchRecordFormat2 && !format2 {
		return nil, nil, fmt.Errorf("%w: a record of format 2", ErrEvsFormatUnsupported)
	}
	if (recordFormat != 0 && recordFormat != evsBatchRecordFormat2) || recordBytes[2] != 0 || recordBytes[3] != 0 {
		return nil, nil, fmt.Errorf("%w: a record's reserved bytes set", ErrEvsPushInvalid)
	}
	length := binary.BigEndian.Uint32(recordBytes[76:80])
	if uint64(len(recordBytes)-EvsBatchRecordHeaderByteCount) != uint64(length) {
		return nil, nil, fmt.Errorf("%w: a record of %d body bytes stating %d", ErrEvsPushInvalid, len(recordBytes)-EvsBatchRecordHeaderByteCount, length)
	}
	record := &EvsBatchRecord{
		Type:            recordType,
		RepoId:          Id(recordBytes[4:20]),
		RefId:           Id(recordBytes[20:36]),
		PushId:          Id(recordBytes[36:52]),
		SignerSidecarId: Id(recordBytes[52:68]),
		TimeMs:          int64(binary.BigEndian.Uint64(recordBytes[68:76])),
		Body:            recordBytes[EvsBatchRecordHeaderByteCount:],
	}
	if recordFormat != evsBatchRecordFormat2 {
		return record, nil, nil
	}
	body, tail, err := splitEvsBatchRecordTail(recordType, record.Body)
	if err != nil {
		return nil, nil, err
	}
	record.Body = body
	return record, tail, nil
}

// Collects one batch's records and writes its bytes: header, records as added, index, trailer.
type EvsBatchWriter struct {
	header  EvsBatchHeader
	records []byte
	index   []byte
	count   uint32
}

// An empty format-1 batch.
func NewEvsBatchWriter(instance uint32, minute uint32, seq uint32, createdMs int64) *EvsBatchWriter {
	return &EvsBatchWriter{header: EvsBatchHeader{Format: evsBatchFormat1, Instance: instance, Minute: minute, Seq: seq, CreatedMs: createdMs}}
}

// The batch's size with nothing more added.
func (self *EvsBatchWriter) ByteCount() int {
	return EvsBatchHeaderByteCount + len(self.records) + len(self.index) + EvsBatchTrailerByteCount
}

// The records added.
func (self *EvsBatchWriter) RecordCount() int {
	return int(self.count)
}

// Whether a record of bodyByteCount fits: within 256 KiB with the rest, or alone within 1 MiB.
func (self *EvsBatchWriter) Fits(bodyByteCount int) bool {
	added := EvsBatchRecordHeaderByteCount + bodyByteCount + evsBatchIndexEntryByteCount
	if self.count == 0 {
		return self.ByteCount()+added <= EvsBatchMaxRecordByteCount
	}
	return self.ByteCount()+added <= EvsBatchMaxByteCount
}

// Adds a record and gives its place in the batch, refusing one that does not fit.
func (self *EvsBatchWriter) Add(record *EvsBatchRecord) (*protocol.EvsPlace, error) {
	if !self.Fits(len(record.Body)) {
		return nil, fmt.Errorf("%w: a record of %d body bytes past the batch's bound", ErrEvsPushInvalid, len(record.Body))
	}
	if record.Type < protocol.EvsBatchRecordType_EVS_BATCH_PUSH || protocol.EvsBatchRecordType_EVS_BATCH_RESEED < record.Type {
		return nil, fmt.Errorf("%w: record type %d", ErrEvsPushInvalid, record.Type)
	}
	encoded := record.encode()
	offset := uint32(EvsBatchHeaderByteCount + len(self.records))
	self.records = append(self.records, encoded...)
	self.index = binary.BigEndian.AppendUint32(self.index, offset)
	self.index = binary.BigEndian.AppendUint32(self.index, uint32(len(encoded)))
	self.count += 1
	return &protocol.EvsPlace{
		Minute: self.header.Minute, Instance: self.header.Instance, Seq: self.header.Seq,
		Offset: offset, Length: uint32(len(encoded)),
	}, nil
}

// The batch's bytes, with its index and trailer. A batch holds at least one record.
func (self *EvsBatchWriter) Bytes() ([]byte, error) {
	if self.count == 0 {
		return nil, fmt.Errorf("%w: a batch of no record", ErrEvsPushInvalid)
	}
	encoded := make([]byte, 0, self.ByteCount())
	encoded = append(encoded, evsBatchMagic...)
	encoded = append(encoded, self.header.Format, 0, 0, 0)
	encoded = binary.BigEndian.AppendUint32(encoded, self.header.Instance)
	encoded = binary.BigEndian.AppendUint32(encoded, self.header.Minute)
	encoded = binary.BigEndian.AppendUint32(encoded, self.header.Seq)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(self.header.CreatedMs))
	encoded = binary.BigEndian.AppendUint32(encoded, self.count)
	encoded = append(encoded, self.records...)
	indexOffset := uint32(len(encoded))
	encoded = append(encoded, self.index...)
	// the trailer's hash covers every byte before the trailer, so not its own index offset
	digest := sha256.Sum256(encoded)
	encoded = binary.BigEndian.AppendUint32(encoded, indexOffset)
	return append(encoded, digest[:]...), nil
}

// A batch read whole and checked: its header, and its records with their places.
type EvsBatch struct {
	Header  EvsBatchHeader
	Records []*EvsBatchRecord
	Places  []*protocol.EvsPlace
	// format 2: each record's tail, nil for a record of format 1's form; nil from a format-1 read
	Tails []*EvsBatchRecordTail
}

// A batch's bytes, checked whole: "URpb" of format 1 (format 2 is ErrEvsFormatUnsupported), within its bound, its
// trailer's hash over every byte before it, and its index naming record_count records that tile the space between
// the header and the index, each parsing.
func ParseEvsBatch(batchBytes []byte) (*EvsBatch, error) {
	return parseEvsBatch(batchBytes, false)
}

// A batch as ParseEvsBatch reads it, and with format2 a format-2 batch too: one holding a format-2 record, whose
// tails come back in Tails, a format past 2 ErrEvsFormatUnsupported, which an evacuator leaves.
func parseEvsBatch(batchBytes []byte, format2 bool) (*EvsBatch, error) {
	if len(batchBytes) < EvsBatchHeaderByteCount+EvsBatchTrailerByteCount || !bytes.HasPrefix(batchBytes, []byte(evsBatchMagic)) {
		return nil, fmt.Errorf("%w: no URpb batch", ErrEvsPushInvalid)
	}
	switch format := batchBytes[4]; {
	case format == evsBatchFormat1:
	case format == evsBatchFormat2 && format2:
	case format == evsBatchFormat2 || (evsBatchFormat2 < format && format2):
		return nil, fmt.Errorf("%w: a batch of format %d", ErrEvsFormatUnsupported, format)
	default:
		return nil, fmt.Errorf("%w: batch format %d", ErrEvsPushInvalid, format)
	}
	if EvsBatchMaxRecordByteCount+EvsBatchHeaderByteCount+evsBatchIndexEntryByteCount+EvsBatchTrailerByteCount < len(batchBytes) {
		return nil, fmt.Errorf("%w: a batch of %d bytes", ErrEvsPushInvalid, len(batchBytes))
	}
	if batchBytes[5] != 0 || batchBytes[6] != 0 || batchBytes[7] != 0 {
		return nil, fmt.Errorf("%w: a batch's reserved bytes set", ErrEvsPushInvalid)
	}
	trailerAt := len(batchBytes) - EvsBatchTrailerByteCount
	digest := sha256.Sum256(batchBytes[:trailerAt])
	if !bytes.Equal(digest[:], batchBytes[trailerAt+4:]) {
		return nil, fmt.Errorf("%w: the trailer's hash", ErrEvsPushInvalid)
	}
	batch := &EvsBatch{Header: EvsBatchHeader{
		Format:    batchBytes[4],
		Instance:  binary.BigEndian.Uint32(batchBytes[8:12]),
		Minute:    binary.BigEndian.Uint32(batchBytes[12:16]),
		Seq:       binary.BigEndian.Uint32(batchBytes[16:20]),
		CreatedMs: int64(binary.BigEndian.Uint64(batchBytes[20:28])),
	}}
	recordCount := binary.BigEndian.Uint32(batchBytes[28:32])
	indexOffset := int(binary.BigEndian.Uint32(batchBytes[trailerAt : trailerAt+4]))
	if recordCount == 0 || indexOffset < EvsBatchHeaderByteCount ||
		uint64(trailerAt-indexOffset) != uint64(recordCount)*evsBatchIndexEntryByteCount {
		return nil, fmt.Errorf("%w: an index of %d records that does not fill its place", ErrEvsPushInvalid, recordCount)
	}
	if 1 < recordCount && EvsBatchMaxByteCount < len(batchBytes) {
		return nil, fmt.Errorf("%w: a batch of %d records and %d bytes", ErrEvsPushInvalid, recordCount, len(batchBytes))
	}
	next := EvsBatchHeaderByteCount
	format2Count := 0
	for at := indexOffset; at < trailerAt; at += evsBatchIndexEntryByteCount {
		offset := int(binary.BigEndian.Uint32(batchBytes[at : at+4]))
		length := int(binary.BigEndian.Uint32(batchBytes[at+4 : at+8]))
		if offset != next || indexOffset-offset < length {
			return nil, fmt.Errorf("%w: records that do not tile the batch", ErrEvsPushInvalid)
		}
		record, tail, err := parseEvsBatchRecord(batchBytes[offset:offset+length], format2)
		if err != nil {
			return nil, err
		}
		if format2 {
			batch.Tails = append(batch.Tails, tail)
			if tail != nil {
				format2Count += 1
			}
		}
		batch.Records = append(batch.Records, record)
		batch.Places = append(batch.Places, &protocol.EvsPlace{
			Minute: batch.Header.Minute, Instance: batch.Header.Instance, Seq: batch.Header.Seq,
			Offset: uint32(offset), Length: uint32(length),
		})
		next = offset + length
	}
	if next != indexOffset {
		return nil, fmt.Errorf("%w: bytes between the records and the index", ErrEvsPushInvalid)
	}
	if format2 && (batch.Header.Format == evsBatchFormat2) != (0 < format2Count) {
		return nil, fmt.Errorf("%w: a batch of format %d holding %d format-2 records", ErrEvsPushInvalid, batch.Header.Format, format2Count)
	}
	return batch, nil
}

// Reads records of one batch by their places, as evs reads a record at its place without the rest of its batch
// (§11.8's read row). What it reads is checked by its record's own layout, and readers check its statement and
// payload by their hashes; only a whole batch's read checks the trailer.
type EvsBatchReader struct {
	in io.ReaderAt
}

// A reader of the batch in holds.
func NewEvsBatchReader(in io.ReaderAt) *EvsBatchReader {
	return &EvsBatchReader{in: in}
}

// The record at place, which must hold a record header and no more than a lone record's bound.
func (self *EvsBatchReader) Record(place *protocol.EvsPlace) (*EvsBatchRecord, error) {
	if place.GetOffset() < EvsBatchHeaderByteCount || place.GetLength() < EvsBatchRecordHeaderByteCount ||
		EvsBatchMaxRecordByteCount < place.GetLength() {
		return nil, fmt.Errorf("%w: a place no record has", ErrEvsPushInvalid)
	}
	recordBytes := make([]byte, place.GetLength())
	if _, err := self.in.ReadAt(recordBytes, int64(place.GetOffset())); err != nil {
		return nil, err
	}
	return ParseEvsBatchRecord(recordBytes)
}

// A push record's body: the statement and the payload as received.
func EvsPushRecordBody(statement []byte, payload []byte) []byte {
	return evsJoinItems([][]byte{statement, payload})
}

// A push or reseed record's statement and payload.
func ParseEvsPushRecordBody(body []byte) ([]byte, []byte, error) {
	items, err := EvsPayloadItems(body)
	if err != nil {
		return nil, nil, err
	}
	if len(items) != 2 {
		return nil, nil, fmt.Errorf("%w: a push record of %d items", ErrEvsPushInvalid, len(items))
	}
	return items[0], items[1], nil
}

// A part record's body: the statement, the part as sent, each receipt's bytes and the head version evs checked it
// at.
func EvsPartRecordBody(statement []byte, part []byte, receipts [][]byte, checkedVersion uint64) []byte {
	items := append([][]byte{statement, part}, receipts...)
	return evsJoinItems(append(items, binary.BigEndian.AppendUint64(nil, checkedVersion)))
}

// A part record's statement, part, receipts and checked head version.
func ParseEvsPartRecordBody(body []byte) ([]byte, []byte, [][]byte, uint64, error) {
	items, err := EvsPayloadItems(body)
	if err != nil {
		return nil, nil, nil, 0, err
	}
	if len(items) < 3 || len(items[len(items)-1]) != 8 {
		return nil, nil, nil, 0, fmt.Errorf("%w: a part record of %d items", ErrEvsPushInvalid, len(items))
	}
	return items[0], items[1], items[2 : len(items)-1], binary.BigEndian.Uint64(items[len(items)-1]), nil
}

// One part as its seal's record names it: where its record is, its changes_root and its first token path.
type EvsSealPart struct {
	Place          *protocol.EvsPlace
	ChangesRoot    [sha256.Size]byte
	FirstTokenPath EvsTokenPath
}

// A seal record's body: the statement, then an item per part.
func EvsSealRecordBody(statement []byte, parts []*EvsSealPart) []byte {
	items := [][]byte{statement}
	for _, part := range parts {
		item := append(EvsPackPlace(part.Place), part.ChangesRoot[:]...)
		items = append(items, append(item, part.FirstTokenPath.Bytes()...))
	}
	return evsJoinItems(items)
}

// A seal record's statement and parts.
func ParseEvsSealRecordBody(body []byte) ([]byte, []*EvsSealPart, error) {
	items, err := EvsPayloadItems(body)
	if err != nil {
		return nil, nil, err
	}
	if len(items) < 1+evsMinPartCount {
		return nil, nil, fmt.Errorf("%w: a seal record of %d items", ErrEvsPushInvalid, len(items))
	}
	parts := []*EvsSealPart{}
	for _, item := range items[1:] {
		if len(item) < EvsPlaceByteCount+sha256.Size+EvsTokenByteCount || (len(item)-EvsPlaceByteCount-sha256.Size)%EvsTokenByteCount != 0 {
			return nil, nil, fmt.Errorf("%w: a seal's part of %d bytes", ErrEvsPushInvalid, len(item))
		}
		place, err := EvsUnpackPlace(item[:EvsPlaceByteCount])
		if err != nil {
			return nil, nil, err
		}
		components := [][]byte{}
		for at := EvsPlaceByteCount + sha256.Size; at < len(item); at += EvsTokenByteCount {
			components = append(components, item[at:at+EvsTokenByteCount])
		}
		tokenPath, err := ParseEvsChangedTokenPath(components)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, &EvsSealPart{
			Place:          place,
			ChangesRoot:    [sha256.Size]byte(item[EvsPlaceByteCount : EvsPlaceByteCount+sha256.Size]),
			FirstTokenPath: tokenPath,
		})
	}
	return items[0], parts, nil
}
