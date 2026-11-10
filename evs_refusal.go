// Refusals (§11.8's refusal row and outcomes): what evs answers instead of a 200, and the 16-byte record the head
// keeps of a refusal it settles, so a retry of the same push id gets the same answer and an unanswered refusal can
// never land later as a commit (I-EVS-3). A record is push_id[0:8] | statement_sha256[0:2] | code u16 | until_s u32,
// until_s UTC seconds rounded up; the head holds at most 8, oldest first, and any head write drops each whose until_s
// its writer's clock has passed (plan-EVS1-format-bytes#7).
//
// EvsRefusalCode is §11.8's fixed code table (EVS-FORMAT.md): codes below 64 are what a record may hold, 64 to 127
// final answers never recorded, and from 128 answers that refuse nothing, which a client retries with the same
// statement. Each code has one status. The codecs' errors map onto the table through EvsRefusalCodeOf.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.8's refusal layout and bounds.
const (
	EvsRefusalByteCount = 16
	// the most records a head holds
	EvsHeadMaxRefusalCount = 8
	// the ranges of the code table
	evsRefusalFinalFrom   = 64
	evsRefusalNothingFrom = 128
)

var (
	// A push, part, seal, batch or window entry that does not parse or breaks its layout or a check that needs no
	// head: §11.8's INVALID.
	ErrEvsPushInvalid = errors.New("evs push invalid")
	// A creation the ref's coming path epoch holds: §18.5's EVS_PATH_EPOCH_DUE, retryable (DESIGN-DETAILS 9.2.8). The
	// planner answers it at once, nothing sent, for a creation on a blocking ref under immediate pressure, and the
	// writer waits it out as it waits out 412 PATH_EPOCH_DUE, giving it to the caller past its bound.
	ErrEvsPathEpochDue = errors.New("evs: EVS_PATH_EPOCH_DUE: a creation waits for the ref's path epoch")
	// A refusal record or code §11.8 does not have.
	ErrEvsRefusalInvalid = errors.New("evs refusal invalid")
)

// The status each code answers with (EVS-FORMAT.md's table).
var evsRefusalStatuses = map[protocol.EvsRefusalCode]int{
	protocol.EvsRefusalCode_EVS_REFUSAL_SCOPE:              403,
	protocol.EvsRefusalCode_EVS_REFUSAL_TIME_STALE:         409,
	protocol.EvsRefusalCode_EVS_REFUSAL_REPO_KEYING:        409,
	protocol.EvsRefusalCode_EVS_REFUSAL_REPO_DELETED:       409,
	protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_PAYMENT:      402,
	protocol.EvsRefusalCode_EVS_REFUSAL_QUOTA_LIMIT:        403,
	protocol.EvsRefusalCode_EVS_REFUSAL_CLUSTER_FULL:       507,
	protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED:        412,
	protocol.EvsRefusalCode_EVS_REFUSAL_INDEX_EPOCH:        409,
	protocol.EvsRefusalCode_EVS_REFUSAL_MAP_PARTS:          409,
	protocol.EvsRefusalCode_EVS_REFUSAL_EPOCH_SOURCES_FULL: 412,
	protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH_DUE:     412,
	protocol.EvsRefusalCode_EVS_REFUSAL_DIRECTORY_FULL:     409,
	protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_GONE:       409,
	protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING:         409,
	protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_UNKNOWN:       409,
	protocol.EvsRefusalCode_EVS_REFUSAL_SLOT_STALE:         409,
	protocol.EvsRefusalCode_EVS_REFUSAL_NOTHING_TO_ERASE:   409,
	protocol.EvsRefusalCode_EVS_REFUSAL_DROPPED:            409,
	protocol.EvsRefusalCode_EVS_REFUSAL_DROP_PATH:          409,
	protocol.EvsRefusalCode_EVS_REFUSAL_DROP_CONSENT:       409,
	protocol.EvsRefusalCode_EVS_REFUSAL_DROP_STATE:         409,
	protocol.EvsRefusalCode_EVS_REFUSAL_DROP_BOUNDARY:      409,
	protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST:          409,
	protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED: 409,
	protocol.EvsRefusalCode_EVS_REFUSAL_REF_MODE:           409,
	protocol.EvsRefusalCode_EVS_REFUSAL_PUSH_ID_REUSED:     409,
	protocol.EvsRefusalCode_EVS_REFUSAL_NON_FAST_FORWARD:   409,
	protocol.EvsRefusalCode_EVS_REFUSAL_BASE_STALE:         409,
	protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT:      409,
	protocol.EvsRefusalCode_EVS_REFUSAL_PATH_EPOCH:         412,
	protocol.EvsRefusalCode_EVS_REFUSAL_SHREDDING:          409,
	protocol.EvsRefusalCode_EVS_REFUSAL_DROP_KIND:          409,
	protocol.EvsRefusalCode_EVS_REFUSAL_SEGMENT_STALE:      409,
	protocol.EvsRefusalCode_EVS_REFUSAL_STATEMENT_MISSING:  409,
	protocol.EvsRefusalCode_EVS_REFUSAL_GROUP_NOT_READY:    409,
	protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE:         409,
	protocol.EvsRefusalCode_EVS_REFUSAL_INVALID:            400,
	protocol.EvsRefusalCode_EVS_REFUSAL_NOT_FOUND:          404,
	protocol.EvsRefusalCode_EVS_REFUSAL_PARTS_MISSING:      409,
	protocol.EvsRefusalCode_EVS_REFUSAL_BUSY:               429,
	protocol.EvsRefusalCode_EVS_REFUSAL_FOLD_BEHIND:        429,
	protocol.EvsRefusalCode_EVS_REFUSAL_TIME_AHEAD:         429,
	protocol.EvsRefusalCode_EVS_REFUSAL_RESOURCE_EXHAUSTED: 429,
	protocol.EvsRefusalCode_EVS_REFUSAL_WAIT:               429,
	protocol.EvsRefusalCode_EVS_REFUSAL_UNAVAILABLE:        503,
}

// The HTTP status code answers with, and false for a code the table does not have.
func EvsRefusalStatus(code protocol.EvsRefusalCode) (int, bool) {
	status, ok := evsRefusalStatuses[code]
	return status, ok
}

// Whether a refusal with code may be recorded in the head: codes 1 to 63.
func EvsRefusalRecordable(code protocol.EvsRefusalCode) bool {
	_, ok := evsRefusalStatuses[code]
	return ok && code < evsRefusalFinalFrom
}

// Whether code refuses nothing, so the client retries the same statement: codes from 128.
func EvsRefusalRefusesNothing(code protocol.EvsRefusalCode) bool {
	_, ok := evsRefusalStatuses[code]
	return ok && evsRefusalNothingFrom <= code
}

// The refusal code an error from this package's codecs answers with: FORMAT_UNSUPPORTED for a format-2 construct,
// format 2's VERSIONING, DROP_LIST and DROP_STATE for what its codecs refuse so, and INVALID for anything else.
func EvsRefusalCodeOf(err error) protocol.EvsRefusalCode {
	switch {
	case errors.Is(err, ErrEvsFormatUnsupported):
		return protocol.EvsRefusalCode_EVS_REFUSAL_FORMAT_UNSUPPORTED
	case errors.Is(err, ErrEvsVersioning):
		return protocol.EvsRefusalCode_EVS_REFUSAL_VERSIONING
	case errors.Is(err, ErrEvsDropList):
		return protocol.EvsRefusalCode_EVS_REFUSAL_DROP_LIST
	case errors.Is(err, ErrEvsDropState):
		return protocol.EvsRefusalCode_EVS_REFUSAL_DROP_STATE
	}
	return protocol.EvsRefusalCode_EVS_REFUSAL_INVALID
}

// Whether err is evs's 409 MAP_SOURCE (DESIGN-DETAILS 9.2.6): final, a PATH_EPOCH whose map's source evs does not
// hold, holds under another chain or of an epoch no longer current, or a map part whose key holds other bytes. The
// mapper builds its map again on the head as it now stands; MAP_PARTS, recorded, asks only for the parts again.
func IsEvsMapSource(err error) bool {
	return IsEvsRefusal(err, protocol.EvsRefusalCode_EVS_REFUSAL_MAP_SOURCE)
}

// One refusal record of the head.
type EvsRefusal struct {
	PushIdPrefix    [8]byte
	StatementPrefix [2]byte
	Code            protocol.EvsRefusalCode
	// UTC seconds, rounded up, after which a head write drops it
	UntilS uint32
}

// The record of a refusal of pushId's statement with code until untilMs: only a recordable code makes one.
func NewEvsRefusal(pushId Id, statementSha256 [sha256.Size]byte, code protocol.EvsRefusalCode, untilMs int64) (*EvsRefusal, error) {
	if !EvsRefusalRecordable(code) {
		return nil, fmt.Errorf("%w: code %d is not recorded", ErrEvsRefusalInvalid, code)
	}
	if untilMs < 0 {
		return nil, fmt.Errorf("%w: a time before the epoch", ErrEvsRefusalInvalid)
	}
	refusal := &EvsRefusal{Code: code, UntilS: uint32((uint64(untilMs) + 999) / 1000)}
	copy(refusal.PushIdPrefix[:], pushId[:8])
	copy(refusal.StatementPrefix[:], statementSha256[:2])
	return refusal, nil
}

// The 16 bytes.
func (self *EvsRefusal) Encode() []byte {
	encoded := make([]byte, 0, EvsRefusalByteCount)
	encoded = append(encoded, self.PushIdPrefix[:]...)
	encoded = append(encoded, self.StatementPrefix[:]...)
	encoded = binary.BigEndian.AppendUint16(encoded, uint16(self.Code))
	return binary.BigEndian.AppendUint32(encoded, self.UntilS)
}

// Whether it records a refusal of pushId: §11.8's 5a then compares the statement prefix, a mismatch being
// PUSH_ID_REUSED.
func (self *EvsRefusal) RecordsPush(pushId Id) bool {
	return [8]byte(pushId[:8]) == self.PushIdPrefix
}

// Whether it records statementSha256's statement, given RecordsPush.
func (self *EvsRefusal) RecordsStatement(statementSha256 [sha256.Size]byte) bool {
	return [2]byte(statementSha256[:2]) == self.StatementPrefix
}

// Whether a head written at nowMs drops it, its until_s passed.
func (self *EvsRefusal) LapsedAt(nowMs int64) bool {
	return int64(self.UntilS)*1000 <= nowMs
}

// One record from its 16 bytes: a code a record may hold, else ErrEvsRefusalInvalid.
func DecodeEvsRefusal(encoded []byte) (*EvsRefusal, error) {
	if len(encoded) != EvsRefusalByteCount {
		return nil, fmt.Errorf("%w: a record of %d bytes", ErrEvsRefusalInvalid, len(encoded))
	}
	refusal := &EvsRefusal{
		PushIdPrefix:    [8]byte(encoded[0:8]),
		StatementPrefix: [2]byte(encoded[8:10]),
		Code:            protocol.EvsRefusalCode(binary.BigEndian.Uint16(encoded[10:12])),
		UntilS:          binary.BigEndian.Uint32(encoded[12:16]),
	}
	if !EvsRefusalRecordable(refusal.Code) {
		return nil, fmt.Errorf("%w: code %d in a record", ErrEvsRefusalInvalid, refusal.Code)
	}
	return refusal, nil
}

// A head's refused field: whole 16-byte records, at most 8.
func DecodeEvsRefusals(refused []byte) ([]*EvsRefusal, error) {
	if len(refused)%EvsRefusalByteCount != 0 || EvsHeadMaxRefusalCount*EvsRefusalByteCount < len(refused) {
		return nil, fmt.Errorf("%w: a refused field of %d bytes", ErrEvsRefusalInvalid, len(refused))
	}
	refusals := make([]*EvsRefusal, 0, len(refused)/EvsRefusalByteCount)
	for at := 0; at < len(refused); at += EvsRefusalByteCount {
		refusal, err := DecodeEvsRefusal(refused[at : at+EvsRefusalByteCount])
		if err != nil {
			return nil, err
		}
		refusals = append(refusals, refusal)
	}
	return refusals, nil
}

// The refused field of refusals, oldest first, refusing more than 8.
func EncodeEvsRefusals(refusals []*EvsRefusal) ([]byte, error) {
	if EvsHeadMaxRefusalCount < len(refusals) {
		return nil, fmt.Errorf("%w: %d records", ErrEvsRefusalInvalid, len(refusals))
	}
	refused := make([]byte, 0, len(refusals)*EvsRefusalByteCount)
	for _, refusal := range refusals {
		refused = append(refused, refusal.Encode()...)
	}
	return refused, nil
}
