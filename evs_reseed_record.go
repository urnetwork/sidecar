//go:build !ios_extension

// A re-seeded push's records as readers meet them (§11.8's record row, §11.13's re-seed row; QD-725, QD-818). A
// one-part push re-seeds as one EVS_BATCH_RESEED record holding a push record's body, its statement and payload, at
// the place its version's window entry names. A push in parts re-seeds as one EVS_BATCH_RESEED record per part, each
// holding a part record's body (its statement, the part as sent, which carries its index under the statement's
// count, no receipts, since a re-seed takes segments from seg/, and the head version evs checked it at), beside an
// EVS_BATCH_SEAL record that names their places as a pushed seal does.
//
// The two bodies are told apart by where the record is named: a reader takes a reseed record at a seal's part place
// as it takes an EVS_BATCH_PART record, when its body parses as a part's, and anywhere else as a one-part push's. A
// push body holds two items and a part body at least three, the last of 8 bytes, so neither parses as the other, and
// a reseed record holding a part at a version's place, or one holding a push at a seal's part place, is refused. The
// type stays the mark the reseed route's slot rule reads.

package sidecar

import (
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// The record at a seal's part place: an EVS_BATCH_PART record, or a re-seeded push's part, an EVS_BATCH_RESEED record
// whose body parses as a part record's. Its statement, part, receipts and the head version evs checked it at;
// ErrEvsPushInvalid for a record of any other type or a body that is no part's.
func ParseEvsSealPartRecord(record *EvsBatchRecord) ([]byte, []byte, [][]byte, uint64, error) {
	switch record.Type {
	case protocol.EvsBatchRecordType_EVS_BATCH_PART, protocol.EvsBatchRecordType_EVS_BATCH_RESEED:
		return ParseEvsPartRecordBody(record.Body)
	}
	return nil, nil, nil, 0, fmt.Errorf("%w: a record of type %d at a seal's part place", ErrEvsPushInvalid, record.Type)
}

// Whether record is a re-seeded push's part: an EVS_BATCH_RESEED record whose body parses as a part record's, which
// stands only at its seal's part place. A reader that meets a record without knowing where it is named, evacuation's
// above all, tells the two reseed bodies apart by this.
func EvsReseedRecordHoldsPart(record *EvsBatchRecord) bool {
	if record.Type != protocol.EvsBatchRecordType_EVS_BATCH_RESEED {
		return false
	}
	_, _, _, _, err := ParseEvsPartRecordBody(record.Body)
	return err == nil
}
