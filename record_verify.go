// RECORD.md section 5.5's per-entry checks, on every leg, and record_alarm's one sink, RecordAlarm: every alarm the
// record raises, from the reader, the ingester and the writer, is one RecordAlarm, which the Sidecar turns into §5.4's
// record_alarm event (plan-RECORD-alarm-kinds).
//
// A reader verifies an entry in stream order: the push carrying it verifies by §11.8's replay, which the RecordStreams
// binding does before it returns a version (RECORD-M3-12, EVS1-M2-23's EvsVerifier), so a version reaching here has
// passed step 1. VerifyRecordEntry runs steps 2 and 3, the header's signature over its received bytes under the
// writer's identity key, and the writer's right where the entry came in; the chain (step 4) is record_pins.go's, and
// the body and kind (steps 5 and 6) record_reader.go's.
//
// Package-level functions are safe for concurrent use.

package sidecar

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol/bridge"
)

// One alarm the record raises.
type RecordAlarm struct {
	Reason SidecarRecordAlarm
	// The log it concerns.
	LogId Id
	// The writer or signer it names, nil where none is known.
	SidecarId *Id
}

// An entry fails section 5.5's header or right step: a reader ignores it and alarms bad_entry, an ingester consumes
// it unrecorded.
var ErrRecordEntryRefused = errors.New("record entry refused")

// Where an entry came in, which decides where its writer's right is judged (RECORD.md section 5.5's right step).
type RecordEntryArrival struct {
	// The stream holding it: its writer's own, or an ingester's.
	StreamSidecarId Id
	// The pin the push holding it declared.
	PushPin *bridge.AuthPin
}

// The header of an entry that passed steps 2 and 3, with its stored Signed.
type RecordVerifiedHeader struct {
	Header *StoredRecordHeader
	Signed *bridge.Signed
	// The Signed's bytes as stored, which header_sha256 covers.
	SignedBytes []byte
}

// Steps 2 and 3 of RECORD.md section 5.5 for one entry of logId, given the state now: the header's Signed verifies
// under the writer's identity key, as signed by writer_sidecar_id, for this log; and the writer could write or
// deposit here where the entry came in. In the writer's own stream that is the push's pin, at which it writes. In an
// ingester's stream it is the position policy_version names, which may not pass the ingester's pin, at which it
// writes or deposits, the ingester having judged the deposit's own pin (section 5.4's right step); the ingester itself
// writes at its push's pin. Either way no compromise revocation of the writer from a since_n at or before that
// position stands. ErrRecordAuthAhead is a pin this state has not reached: the caller waits, rather than judges.
func VerifyRecordEntry(auth RecordAuthView, logId Id, signedBytes []byte, arrival *RecordEntryArrival) (*RecordVerifiedHeader, error) {
	header, signed, err := recordSignedHeader(signedBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRecordEntryRefused, err)
	}
	if signed.GetType() != uint32(bridge.SignedType_SIGNED_RECORD_HEADER) {
		return nil, fmt.Errorf("%w: a Signed of type %#x", ErrRecordEntryRefused, signed.GetType())
	}
	writerId := recordIdOf(header.Header.GetWriterSidecarId())
	if !bytes.Equal(signed.GetSignerId(), writerId[:]) {
		return nil, fmt.Errorf("%w: signed by another than its writer", ErrRecordEntryRefused)
	}
	if !bytes.Equal(header.Header.GetLogId(), logId[:]) {
		return nil, fmt.Errorf("%w: an entry of another log", ErrRecordEntryRefused)
	}
	if arrival == nil || arrival.PushPin == nil {
		return nil, fmt.Errorf("%w: no push pin", ErrRecordEntryRefused)
	}
	pushView, err := auth.At(arrival.PushPin)
	if err != nil {
		return nil, recordAuthRefusal(err)
	}
	var judged RecordAuthView
	var position uint64
	if arrival.StreamSidecarId == writerId {
		if !pushView.Writes(logId, writerId) {
			return nil, fmt.Errorf("%w: its writer writes no stream here", ErrRecordEntryRefused)
		}
		judged = pushView
		position = arrival.PushPin.GetVersion()
	} else {
		if !pushView.Writes(logId, arrival.StreamSidecarId) {
			return nil, fmt.Errorf("%w: its ingester writes no stream here", ErrRecordEntryRefused)
		}
		position = header.Header.GetPolicyVersion()
		if arrival.PushPin.GetVersion() < position {
			return nil, fmt.Errorf("%w: policy_version past the ingester's pin", ErrRecordEntryRefused)
		}
		judged, err = auth.AtPosition(position)
		if err != nil {
			return nil, recordAuthRefusal(err)
		}
		if !judged.Writes(logId, writerId) && !judged.Deposits(logId, writerId) {
			return nil, fmt.Errorf("%w: its writer neither writes nor deposits here at its policy_version", ErrRecordEntryRefused)
		}
	}
	if since, compromised := auth.CompromisedSince(writerId); compromised && since <= position {
		return nil, fmt.Errorf("%w: its writer's compromise revocation reaches it", ErrRecordEntryRefused)
	}
	key := judged.IdentityKey(writerId)
	if len(key) == 0 {
		return nil, fmt.Errorf("%w: no identity key for its writer", ErrRecordEntryRefused)
	}
	if err := bridge.VerifySigned(signed, RecordEntryPurpose, bridge.SignedType_SIGNED_RECORD_HEADER, bridge.SignedKeyAlgEd25519, key); err != nil {
		return nil, fmt.Errorf("%w: its signature: %v", ErrRecordEntryRefused, err)
	}
	return &RecordVerifiedHeader{Header: header, Signed: signed, SignedBytes: bytes.Clone(signedBytes)}, nil
}

// A state's refusal to judge a pin: ahead waits, and every other one refuses the entry.
func recordAuthRefusal(err error) error {
	if errors.Is(err, ErrRecordAuthAhead) {
		return err
	}
	return fmt.Errorf("%w: %v", ErrRecordEntryRefused, err)
}
