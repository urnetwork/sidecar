// Elided records on the read route (§11.9's serve row; D-EVS-63, I-EVS-1, FS-94; DESIGN-DETAILS 10.2.9's records row;
// EVS2-M10-10): when evs serves a push or part by push id and a dropped entry version's chain holds an inline
// record, its entry bytes are sent as zeros of the same length, from its drop's not_before_ms.
// Offsets, lengths and frames stay valid, every other entry version keeps its own hash, and a reader that finds an
// entry version all zero under a path it holds as dropped raises no alarm (EVS2-M10-22's replay over an elided part).
// A record with no inline record costs nothing: DropOf runs only for an entry version holding one. A seal's record
// holds no entry version, and passes as stored.
//
// A staged tail that includes a withheld segment or a version this read answered collected is served in
// evacuation's form, retaining the purge list.
// Legacy one-part records lose their unsigned slot bodies just as the current writer removes them at commit.
// The signed bytes still verify, available segments can be requested by range, and the cache keeps the original.

package evsservice

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The record committed at version, in its public form. Apply object withholding before sending any cached bytes.
func (self *readAttempt) elideRecord(recordBytes []byte, version uint64) ([]byte, error) {
	var record *sidecar.EvsBatchRecord
	var tail *sidecar.EvsBatchRecordTail
	var err error
	format2 := self.engine.format2Instance()
	if format2 {
		record, tail, err = sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	} else {
		record, err = sidecar.ParseEvsBatchRecord(recordBytes)
	}
	if err != nil {
		return nil, err
	}
	changed := false
	partRecord := record.Type == protocol.EvsBatchRecordType_EVS_BATCH_PART || sidecar.EvsReseedRecordHoldsPart(record)
	if !partRecord && (record.Type == protocol.EvsBatchRecordType_EVS_BATCH_PUSH || record.Type == protocol.EvsBatchRecordType_EVS_BATCH_RESEED) {
		signed, payload, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		public, err := sidecar.EvsRecordPayload(payload)
		if err != nil {
			return nil, err
		}
		if len(public) != len(payload) {
			record.Body = sidecar.EvsPushRecordBody(signed, public)
			changed = true
		}
	}
	if tail != nil && len(tail.Staged) > 0 {
		ids, err := self.withheldIds()
		if err != nil {
			return nil, err
		}
		if len(ids) > 0 || len(self.staged) > 0 {
			segments, err := tail.StagedSegments()
			if err != nil {
				return nil, err
			}
			for _, segment := range segments {
				id := sha256.Sum256(segment)
				staged := self.staged[id]
				if ids[DropSegmentId(id)] || (staged != nil && staged.collected) {
					tail = &sidecar.EvsBatchRecordTail{PurgeList: tail.PurgeList}
					changed = true
					break
				}
			}
		}
	}
	if changed {
		recordBytes = record.Bytes(tail)
	}
	if !format2 {
		return recordBytes, nil
	}
	return self.elideInlineEntries(recordBytes, record, partRecord, version)
}

// Zero only the signed change's entry field, keeping the original slices intact for verification and other reads.
func (self *readAttempt) elideInlineEntries(recordBytes []byte, record *sidecar.EvsBatchRecord, partRecord bool, version uint64) ([]byte, error) {
	table, err := self.dropTable()
	if err != nil || table == nil {
		return recordBytes, err
	}
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return nil, err
	}
	if record.Type == protocol.EvsBatchRecordType_EVS_BATCH_SEAL {
		return recordBytes, nil
	}
	var changes []*sidecar.EvsCheckedChange
	if partRecord {
		_, partBytes, _, _, err := sidecar.ParseEvsSealPartRecord(record)
		if err != nil {
			return nil, err
		}
		part, err := sidecar.EvsCheckStoredPart(statement, partBytes)
		if err != nil {
			return nil, err
		}
		changes = part.Changes
	} else {
		_, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return nil, err
		}
		changes = payload.Changes
	}
	served := recordBytes
	var servedEntries [][]byte
	nextEntry := 0
	for _, change := range changes {
		if !change.WritesEntry() {
			continue
		}
		index := nextEntry
		nextEntry++
		if !evsEntryHoldsInline(change.EntryVersion) {
			continue
		}
		entry, err := parseEvsEntryVersion(change.EntryVersion)
		if err != nil {
			return nil, err
		}
		verdict, err := self.dropOf(&readDropTarget{
			epoch:         statement.Push.GetPathEpoch(),
			tokenPath:     change.TokenPath,
			version:       entry.GetVersion(),
			commitVersion: version,
			entrySha256:   sha256.Sum256(change.EntryVersion),
		})
		if err != nil {
			return nil, err
		}
		if verdict == nil || verdict.pending {
			continue
		}
		if servedEntries == nil {
			served = bytes.Clone(recordBytes)
			body := served[sidecar.EvsBatchRecordHeaderByteCount:][:len(record.Body)]
			servedEntries, err = readRecordEntries(body, partRecord)
			if err != nil {
				return nil, err
			}
		}
		if len(servedEntries) <= index || !bytes.Equal(servedEntries[index], change.EntryVersion) {
			return nil, fmt.Errorf("%w: a record's entry differs from its checked change", ErrEvsStatementMismatch)
		}
		clear(servedEntries[index])
	}
	return served, nil
}

// The entry fields in a private copy of a checked record body, in write order. Only these wire spans can be
// cleared: equal bytes may belong to a kept entry, the signed statement, or another part field.
func readRecordEntries(body []byte, part bool) ([][]byte, error) {
	items, err := sidecar.EvsPayloadItems(body)
	if err != nil || len(items) < 2 {
		return nil, fmt.Errorf("%w: a record lacks its statement or payload", ErrEvsStatementMismatch)
	}
	if !part {
		payload, err := sidecar.ParseEvsPayloadFormat2(items[1])
		if err != nil {
			return nil, err
		}
		return sidecar.EvsPayloadItems(payload.Section(protocol.EvsPayloadSection_EVS_PAYLOAD_ENTRY_VERSIONS))
	}
	var entries [][]byte
	for rest := items[1]; len(rest) > 0; {
		number, wireType, tagSize := protowire.ConsumeTag(rest)
		if tagSize < 0 {
			return nil, protowire.ParseError(tagSize)
		}
		rest = rest[tagSize:]
		if number == 4 && wireType == protowire.BytesType { // EvsPushPart.entry_versions
			entry, size := protowire.ConsumeBytes(rest)
			if size < 0 {
				return nil, protowire.ParseError(size)
			}
			entries = append(entries, entry)
			rest = rest[size:]
			continue
		}
		size := protowire.ConsumeFieldValue(number, wireType, rest)
		if size < 0 {
			return nil, protowire.ParseError(size)
		}
		rest = rest[size:]
	}
	return entries, nil
}
