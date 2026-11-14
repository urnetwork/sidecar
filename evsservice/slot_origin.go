// A slot object's origin (DESIGN-DETAILS 14.2.2; QD-765): the statement whose create stored it, written by evs in
// object metadata on slot/ objects, beside entry.go's entry-state, which is the pattern. Step 6's create If-None-Match
// carries it in the one PUT that stores the bytes, and that create is atomic and exclusive, so exactly one statement
// is the origin of an object for as long as the object stands. No route returns it to a client, and no message a
// client signs, sends or reads changes.
//
//	key    origin
//	value  1.p.<push_id>.<statement_prefix>.<ref_id>.<signer_sidecar_id>.<base_version>.<path_epoch>.<mode>
//	       a push's or a seal's slot: its statement's fields; ids in lower hex, 32 characters each; numbers in
//	       decimal; mode f (file) or g (git)
//	       1.r   a re-seeded slot (EVSB-M2-20)
//	none   no origin key, a value past EvsSettings.SlotOriginMaxByteCount (190 B), or one that does not parse to one
//	       of the two forms: the object is no statement's
//
// push_id and statement_prefix name the statement, the pair a head's window entry and a log page name a commit by,
// so "this attempt's own" and "this record's own" are one comparison of 32 bytes. The other five fields are what a
// takeover tests (14.2.4), so evs can run EvsPushStandingIn for the origin's statement without finding its record.
// All seven are already in the push's batch record (evs-12), and §2.8's evs-5 row says the slot holds them too.
//
// The value is versioned by its first field, and compared as parsed fields, never as a string. A reader treats an
// origin it cannot parse as no statement's, which is the closed direction everywhere: such an object is never taken
// by step 6 and never deleted by evacuation.

package evsservice

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/protocol"
)

// The object metadata key a slot's origin rides under.
const EvsSlotOriginMetadataKey = "origin"

// The value's fields that are words: its version, its two kinds and a push's two modes.
const (
	evsSlotOriginVersion    = "1"
	evsSlotOriginPushKind   = "p"
	evsSlotOriginReseedKind = "r"
	evsSlotOriginFileMode   = "f"
	evsSlotOriginGitMode    = "g"
	evsSlotOriginSeparator  = "."
)

// A statement whose fields no origin can hold: an id that is not 16 bytes, or a ref mode neither git nor file.
var ErrEvsSlotOriginInvalid = errors.New("evs slot origin invalid")

// Whose a slot object is.
type EvsSlotOriginKind int

const (
	// No statement's: no origin key, or a value that does not parse.
	EvsSlotOriginNone EvsSlotOriginKind = iota
	// A push's or a seal's statement, which step 6 wrote it for.
	EvsSlotOriginPush
	// A re-seed's (EVSB-M2-20), counted committed and never any push's.
	EvsSlotOriginReseed
)

// One origin. The fields past Kind are set for a push's only.
type EvsSlotOrigin struct {
	Kind EvsSlotOriginKind
	// The statement's name: its push id and the first 16 bytes of its SHA-256.
	PushId          sidecar.Id
	StatementPrefix [16]byte
	// What the takeover tests: the statement's ref and signer, its base version, its declared path epoch and its
	// ref mode.
	RefId           sidecar.Id
	SignerSidecarId sidecar.Id
	BaseVersion     uint64
	PathEpoch       uint64
	GitMode         bool
}

// The origin step 6 writes for statement's slots: its push id, statement prefix, ref, signer, base version, declared
// path epoch and mode.
func EvsSlotOriginOf(statement *sidecar.EvsStatement) (EvsSlotOrigin, error) {
	push := statement.Push
	pushId, pushErr := sidecar.IdFromBytes(push.GetPushId())
	refId, refErr := sidecar.IdFromBytes(push.GetRefId())
	signerId, signerErr := sidecar.IdFromBytes(push.GetSignerSidecarId())
	if pushErr != nil || refErr != nil || signerErr != nil {
		return EvsSlotOrigin{}, fmt.Errorf("%w: a statement id that is not 16 bytes", ErrEvsSlotOriginInvalid)
	}
	var gitMode bool
	switch protocol.EvsRefMode(push.GetRefMode()) {
	case protocol.EvsRefMode_EVS_REF_GIT:
		gitMode = true
	case protocol.EvsRefMode_EVS_REF_FILE:
	default:
		return EvsSlotOrigin{}, fmt.Errorf("%w: ref mode %d", ErrEvsSlotOriginInvalid, push.GetRefMode())
	}
	return EvsSlotOrigin{
		Kind:            EvsSlotOriginPush,
		PushId:          pushId,
		StatementPrefix: [16]byte(statement.Sha256[:16]),
		RefId:           refId,
		SignerSidecarId: signerId,
		BaseVersion:     push.GetBaseVersion(),
		PathEpoch:       push.GetPathEpoch(),
		GitMode:         gitMode,
	}, nil
}

// A re-seeded slot's origin, 1.r.
func EvsSlotOriginReseeded() EvsSlotOrigin {
	return EvsSlotOrigin{Kind: EvsSlotOriginReseed}
}

// The value, empty for none.
func (self EvsSlotOrigin) Encode() string {
	switch self.Kind {
	case EvsSlotOriginPush:
		mode := evsSlotOriginFileMode
		if self.GitMode {
			mode = evsSlotOriginGitMode
		}
		return strings.Join([]string{
			evsSlotOriginVersion,
			evsSlotOriginPushKind,
			sidecar.EvsKeyId(self.PushId),
			hex.EncodeToString(self.StatementPrefix[:]),
			sidecar.EvsKeyId(self.RefId),
			sidecar.EvsKeyId(self.SignerSidecarId),
			strconv.FormatUint(self.BaseVersion, 10),
			strconv.FormatUint(self.PathEpoch, 10),
			mode,
		}, evsSlotOriginSeparator)
	case EvsSlotOriginReseed:
		return evsSlotOriginVersion + evsSlotOriginSeparator + evsSlotOriginReseedKind
	}
	return ""
}

// The metadata a create carries for the origin, nil for none, or ErrEvsSlotOriginInvalid when the value passes
// maxByteCount, which a reader would take for none.
func (self EvsSlotOrigin) Metadata(maxByteCount int) (map[string]string, error) {
	value := self.Encode()
	if value == "" {
		return nil, nil
	}
	if maxByteCount < len(value) {
		return nil, fmt.Errorf("%w: %d bytes, past %d", ErrEvsSlotOriginInvalid, len(value), maxByteCount)
	}
	return map[string]string{EvsSlotOriginMetadataKey: value}, nil
}

// The longest value a version-1 origin takes: a push's with both numbers at their largest. EvsSettings holds
// SlotOriginMaxByteCount at or above it.
func evsSlotOriginLongestByteCount() int {
	return len(EvsSlotOrigin{Kind: EvsSlotOriginPush, BaseVersion: math.MaxUint64, PathEpoch: math.MaxUint64}.Encode())
}

// Whether the origin is the statement pushId and statementPrefix name: a push's, with both equal.
func (self EvsSlotOrigin) IsStatement(pushId sidecar.Id, statementPrefix [16]byte) bool {
	return self.Kind == EvsSlotOriginPush && self.PushId == pushId && self.StatementPrefix == statementPrefix
}

// Whether two origins name one statement: both a push's, by push id and statement prefix.
func (self EvsSlotOrigin) SameStatement(other EvsSlotOrigin) bool {
	return other.Kind == EvsSlotOriginPush && self.IsStatement(other.PushId, other.StatementPrefix)
}

// The origin a slot object's metadata holds. Any error is none: no key, a value past maxByteCount, another version,
// a kind it does not know, a field missing or extra, an id that is not 32 lowercase hex characters, a number that is
// not canonical decimal, or a mode neither f nor g.
func ParseEvsSlotOrigin(metadata map[string]string, maxByteCount int) EvsSlotOrigin {
	value, ok := metadata[EvsSlotOriginMetadataKey]
	if !ok || maxByteCount < len(value) {
		return EvsSlotOrigin{}
	}
	fields := strings.Split(value, evsSlotOriginSeparator)
	if len(fields) < 2 || fields[0] != evsSlotOriginVersion {
		return EvsSlotOrigin{}
	}
	switch {
	case fields[1] == evsSlotOriginReseedKind && len(fields) == 2:
		return EvsSlotOriginReseeded()
	case fields[1] != evsSlotOriginPushKind || len(fields) != 9:
		return EvsSlotOrigin{}
	}
	id := func(text string) ([16]byte, bool) {
		var parsed [16]byte
		if len(text) != 2*len(parsed) || strings.ToLower(text) != text {
			return parsed, false
		}
		if _, err := hex.Decode(parsed[:], []byte(text)); err != nil {
			return parsed, false
		}
		return parsed, true
	}
	number := func(text string) (uint64, bool) {
		parsed, err := strconv.ParseUint(text, 10, 64)
		return parsed, err == nil && strconv.FormatUint(parsed, 10) == text
	}
	pushId, pushOk := id(fields[2])
	statementPrefix, prefixOk := id(fields[3])
	refId, refOk := id(fields[4])
	signerId, signerOk := id(fields[5])
	baseVersion, baseOk := number(fields[6])
	pathEpoch, epochOk := number(fields[7])
	if !pushOk || !prefixOk || !refOk || !signerOk || !baseOk || !epochOk {
		return EvsSlotOrigin{}
	}
	var gitMode bool
	switch fields[8] {
	case evsSlotOriginGitMode:
		gitMode = true
	case evsSlotOriginFileMode:
	default:
		return EvsSlotOrigin{}
	}
	return EvsSlotOrigin{
		Kind:            EvsSlotOriginPush,
		PushId:          sidecar.Id(pushId),
		StatementPrefix: statementPrefix,
		RefId:           sidecar.Id(refId),
		SignerSidecarId: sidecar.Id(signerId),
		BaseVersion:     baseVersion,
		PathEpoch:       pathEpoch,
		GitMode:         gitMode,
	}
}
