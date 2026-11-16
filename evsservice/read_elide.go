// Elided records on the read route (§11.9's serve row; D-EVS-63, I-EVS-1, FS-94; DESIGN-DETAILS 10.2.9's records row;
// EVS2-M10-10): in a push's or part's record that evs serves by push id, the bytes of each entry version a dropped
// version's whose chain holds an inline record are sent as zeros of the same length, from its drop's not_before_ms.
// Offsets, lengths and frames stay valid, every other entry version keeps its own hash, and a reader that finds an
// entry version all zero under a path it holds as dropped raises no alarm (EVS2-M10-22's replay over an elided part).
// A record with no inline record costs nothing: DropOf runs only for an entry version holding one. A seal's record
// holds no entry version, and passes as stored.
//
// The record's bytes are copied before any is zeroed: the process's record cache keeps them as stored.

package evsservice

import (
	"bytes"
	"crypto/sha256"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The record committed at version, as served: recordBytes as stored, or a copy with each dropped inline-holding entry
// version zeroed. A format-1 instance, and a repo that never had a drop, serve it as stored.
func (self *readAttempt) elideRecord(recordBytes []byte, version uint64) ([]byte, error) {
	if !self.engine.format2Instance() {
		return recordBytes, nil
	}
	table, err := self.dropTable()
	if err != nil || table == nil {
		return recordBytes, err
	}
	record, _, err := sidecar.ParseEvsBatchRecordFormat2(recordBytes)
	if err != nil {
		return nil, err
	}
	statement, err := EvsBatchRecordStatement(record)
	if err != nil {
		return nil, err
	}
	var changes []*sidecar.EvsCheckedChange
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PUSH:
		_, payloadBytes, err := sidecar.ParseEvsPushRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		payload, err := sidecar.EvsCheckStoredPayload(statement, payloadBytes)
		if err != nil {
			return nil, err
		}
		changes = payload.Changes
	case protocol.EvsBatchRecordType_EVS_BATCH_PART:
		_, partBytes, _, _, err := sidecar.ParseEvsPartRecordBody(record.Body)
		if err != nil {
			return nil, err
		}
		part, err := sidecar.EvsCheckStoredPart(statement, partBytes)
		if err != nil {
			return nil, err
		}
		changes = part.Changes
	default:
		return recordBytes, nil
	}
	served := recordBytes
	for _, change := range changes {
		if !change.WritesEntry() || !evsEntryHoldsInline(change.EntryVersion) {
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
		at := bytes.Index(served, change.EntryVersion)
		if at < 0 {
			continue
		}
		if &served[0] == &recordBytes[0] {
			served = bytes.Clone(recordBytes)
		}
		clear(served[at : at+len(change.EntryVersion)])
	}
	return served, nil
}
