// The head's window (§11.8's entry row, D-EVS-29): one 64-byte entry per recent version, oldest first, naming where
// the version's record is and enough of its statement to check it and to filter by path. An entry is push_id 16 |
// statement_sha256[0:16] | place 20 | paths_digest u64 | flags u32 (plan-EVS1-format-bytes#7). The flags' bits are
// EvsWindowFlag's: 0 the push creates a path, 1 its change list is in the payload under changes_root, 2 PATH_EPOCH, 3
// FORCE, DELETE, BASE or ERASE; 4 and 5 are format 2's, which format 1 ignores on read; 6 to 15 are none, and a reader
// refuses them; 16 to 31 hold the change count, saturating. In format 2, bit 4 marks a push that replaces or removes a
// versionless version, its record listing the purge's candidates or marked, which evs sets as it lists them, and bit
// 5 a DROP push, a cancel included, set from the statement's flag; a reader takes both as hints, the statement
// deciding.
//
// A place, where a batch record's bytes are, packs to 20 bytes: minute, instance, seq, offset and length, each u32.
// A log page holds its versions' entries the same way, so readers check statements against them.
//
// A wrong entry can only send a reader to a statement that does not match its hash, which breaks the chain and
// alarms (§11.8's trust row). On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.8's entry and place layouts and bounds.
const (
	EvsWindowEntryByteCount = 64
	EvsPlaceByteCount       = 20
	// a window's bound while folds lag (§11.7)
	EvsWindowMaxEntryCount = 255
	// the flag bits format 1 neither writes nor refuses
	evsWindowIgnoredFlags = uint32(protocol.EvsWindowFlag_EVS_WINDOW_VERSIONLESS_REPLACED) |
		uint32(protocol.EvsWindowFlag_EVS_WINDOW_DROP)
	// the bits format 1 writes
	evsWindowKnownFlags = uint32(protocol.EvsWindowFlag_EVS_WINDOW_CREATES_PATH) |
		uint32(protocol.EvsWindowFlag_EVS_WINDOW_CHANGES_IN_PAYLOAD) | uint32(protocol.EvsWindowFlag_EVS_WINDOW_PATH_EPOCH) |
		uint32(protocol.EvsWindowFlag_EVS_WINDOW_REWRITES_HISTORY)
	evsWindowChangeCountShift = 16
	evsWindowMaxChangeCount   = 0xffff
)

// The 20 bytes of a place.
func EvsPackPlace(place *protocol.EvsPlace) []byte {
	packed := make([]byte, 0, EvsPlaceByteCount)
	packed = binary.BigEndian.AppendUint32(packed, place.GetMinute())
	packed = binary.BigEndian.AppendUint32(packed, place.GetInstance())
	packed = binary.BigEndian.AppendUint32(packed, place.GetSeq())
	packed = binary.BigEndian.AppendUint32(packed, place.GetOffset())
	return binary.BigEndian.AppendUint32(packed, place.GetLength())
}

// A place from its 20 bytes.
func EvsUnpackPlace(packed []byte) (*protocol.EvsPlace, error) {
	if len(packed) != EvsPlaceByteCount {
		return nil, fmt.Errorf("%w: a place of %d bytes", ErrEvsPushInvalid, len(packed))
	}
	return &protocol.EvsPlace{
		Minute:   binary.BigEndian.Uint32(packed[0:4]),
		Instance: binary.BigEndian.Uint32(packed[4:8]),
		Seq:      binary.BigEndian.Uint32(packed[8:12]),
		Offset:   binary.BigEndian.Uint32(packed[12:16]),
		Length:   binary.BigEndian.Uint32(packed[16:20]),
	}, nil
}

// One window entry.
type EvsWindowEntry struct {
	PushId          Id
	StatementPrefix [16]byte
	Place           *protocol.EvsPlace
	PathsDigest     EvsPathsDigest
	Flags           uint32
}

// The entry step 7 appends for a push it checked (§11.8's fill row): its id, its statement's hash, the place its
// batch write returned, the digest of its changed paths (and covering prefixes when not inline), and its flags:
// createsPath from the checks, the list's place, PATH_EPOCH, the history rewrites, and its change count.
func NewEvsWindowEntry(statementSha256 [sha256.Size]byte, push *protocol.EvsPush, changedPaths []EvsTokenPath, coveringPrefixes []EvsTokenPath, createsPath bool, place *protocol.EvsPlace) *EvsWindowEntry {
	entry := &EvsWindowEntry{
		PushId:          Id(push.GetPushId()),
		StatementPrefix: [16]byte(statementSha256[:16]),
		Place:           place,
		PathsDigest:     NewEvsPathsDigest(changedPaths, coveringPrefixes),
	}
	if createsPath {
		entry.Flags |= uint32(protocol.EvsWindowFlag_EVS_WINDOW_CREATES_PATH)
	}
	if len(push.GetChangesRoot()) != 0 {
		entry.Flags |= uint32(protocol.EvsWindowFlag_EVS_WINDOW_CHANGES_IN_PAYLOAD)
	}
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_PATH_EPOCH) != 0 {
		entry.Flags |= uint32(protocol.EvsWindowFlag_EVS_WINDOW_PATH_EPOCH)
	}
	rewrites := uint32(protocol.EvsPushFlag_EVS_PUSH_FORCE) | uint32(protocol.EvsPushFlag_EVS_PUSH_DELETE) |
		uint32(protocol.EvsPushFlag_EVS_PUSH_BASE) | uint32(protocol.EvsPushFlag_EVS_PUSH_ERASE)
	if push.GetFlags()&rewrites != 0 {
		entry.Flags |= uint32(protocol.EvsWindowFlag_EVS_WINDOW_REWRITES_HISTORY)
	}
	// format 2's bit 5; format 1 never commits flag 256, so it never writes it
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) != 0 {
		entry.Flags |= uint32(protocol.EvsWindowFlag_EVS_WINDOW_DROP)
	}
	changeCount := uint64(len(push.GetChanges()))
	if len(push.GetChangesRoot()) != 0 {
		changeCount = uint64(push.GetChangeCount())
	}
	entry.Flags |= uint32(min(changeCount, evsWindowMaxChangeCount)) << evsWindowChangeCountShift
	return entry
}

// The 64 bytes.
func (self *EvsWindowEntry) Encode() []byte {
	encoded := make([]byte, 0, EvsWindowEntryByteCount)
	encoded = append(encoded, self.PushId[:]...)
	encoded = append(encoded, self.StatementPrefix[:]...)
	encoded = append(encoded, EvsPackPlace(self.Place)...)
	encoded = binary.BigEndian.AppendUint64(encoded, uint64(self.PathsDigest))
	return binary.BigEndian.AppendUint32(encoded, self.Flags)
}

// Whether the push created a path: bit 0.
func (self *EvsWindowEntry) CreatesPath() bool {
	return self.Flags&uint32(protocol.EvsWindowFlag_EVS_WINDOW_CREATES_PATH) != 0
}

// Whether its change list is in the payload under changes_root: bit 1.
func (self *EvsWindowEntry) ChangesInPayload() bool {
	return self.Flags&uint32(protocol.EvsWindowFlag_EVS_WINDOW_CHANGES_IN_PAYLOAD) != 0
}

// Whether it is a PATH_EPOCH push: bit 2.
func (self *EvsWindowEntry) PathEpoch() bool {
	return self.Flags&uint32(protocol.EvsWindowFlag_EVS_WINDOW_PATH_EPOCH) != 0
}

// Whether it was FORCE, DELETE, BASE or ERASE: bit 3.
func (self *EvsWindowEntry) RewritesHistory() bool {
	return self.Flags&uint32(protocol.EvsWindowFlag_EVS_WINDOW_REWRITES_HISTORY) != 0
}

// Whether the push replaced or removed a versionless version, its record listing the purge's candidates: format 2's
// bit 4, a hint.
func (self *EvsWindowEntry) ReplacesVersionless() bool {
	return self.Flags&uint32(protocol.EvsWindowFlag_EVS_WINDOW_VERSIONLESS_REPLACED) != 0
}

// Sets bit 4, which evs does for a push whose step 5 found versionless versions it replaces or removes.
func (self *EvsWindowEntry) SetReplacesVersionless() {
	self.Flags |= uint32(protocol.EvsWindowFlag_EVS_WINDOW_VERSIONLESS_REPLACED)
}

// Whether it is a DROP push, a cancel included: format 2's bit 5, a hint whose body 5h's fence reads.
func (self *EvsWindowEntry) Drop() bool {
	return self.Flags&uint32(protocol.EvsWindowFlag_EVS_WINDOW_DROP) != 0
}

// Its change count, saturating at 65,535.
func (self *EvsWindowEntry) ChangeCount() uint32 {
	return self.Flags >> evsWindowChangeCountShift
}

// Whether a statement is the one the entry names: its push id and its hash's prefix.
func (self *EvsWindowEntry) Names(pushId Id, statementSha256 [sha256.Size]byte) bool {
	return self.PushId == pushId && self.StatementPrefix == [16]byte(statementSha256[:16])
}

// One entry from its 64 bytes. Bits 4 and 5 are kept as read and mean nothing to format 1; any of bits 6 to 15 is
// refused.
func DecodeEvsWindowEntry(encoded []byte) (*EvsWindowEntry, error) {
	if len(encoded) != EvsWindowEntryByteCount {
		return nil, fmt.Errorf("%w: an entry of %d bytes", ErrEvsPushInvalid, len(encoded))
	}
	place, err := EvsUnpackPlace(encoded[32:52])
	if err != nil {
		return nil, err
	}
	entry := &EvsWindowEntry{
		PushId:          Id(encoded[0:16]),
		StatementPrefix: [16]byte(encoded[16:32]),
		Place:           place,
		PathsDigest:     EvsPathsDigest(binary.BigEndian.Uint64(encoded[52:60])),
		Flags:           binary.BigEndian.Uint32(encoded[60:64]),
	}
	lowFlags := entry.Flags & (1<<evsWindowChangeCountShift - 1)
	if lowFlags&^(evsWindowKnownFlags|evsWindowIgnoredFlags) != 0 {
		return nil, fmt.Errorf("%w: window flags %#x", ErrEvsPushInvalid, lowFlags)
	}
	return entry, nil
}

// A window field or log page's window: whole entries, at most 255.
func DecodeEvsWindow(window []byte) ([]*EvsWindowEntry, error) {
	if len(window)%EvsWindowEntryByteCount != 0 || EvsWindowMaxEntryCount*EvsWindowEntryByteCount < len(window) {
		return nil, fmt.Errorf("%w: a window of %d bytes", ErrEvsPushInvalid, len(window))
	}
	entries := make([]*EvsWindowEntry, 0, len(window)/EvsWindowEntryByteCount)
	for at := 0; at < len(window); at += EvsWindowEntryByteCount {
		entry, err := DecodeEvsWindowEntry(window[at : at+EvsWindowEntryByteCount])
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
