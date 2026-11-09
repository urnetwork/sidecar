// Staged segments (§11.7's staged row, EVS-FORMAT.md's format 2 chapter): a versionless version's record that pads,
// as a one-record kind-5 segment, to at most 16 KiB rides in its push or part instead of an upload, so content
// replaced within about a day never reaches the HDDs. Its new-objects item is kind 2 | id | padded_size | upload_day
// 0, its locator {kind 5, id, offset, length, staged}, and it has no receipt. Its bytes travel outside every payload
// hash, as the staged bytes: absent when none, else u32 count, at least 1, then per segment u32 length | its bytes.
// Joined over a push's parts in part order, the staged segments are the kind-2 new-objects items, one each and in
// that order; new_objects_sha256 covers the items, never the bytes.
//
// The checks (§11.6's checks row): each hashes to its item's id, its length is its item's padded_size, and it is a
// kind-5 segment of this repo naming this push, at most 16 KiB and of a Padmé length; another push is
// ErrEvsVersioning, as an upload's is, and any other break ErrEvsPushInvalid. ur/lfs objects never stage
// (plan-EVS2-small-readings#8), which is the writer's rule: evs sees no ref name.
//
// On every leg. Package-level functions are safe for concurrent use.

package sidecar

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.7's staged bound: a staged segment pads to at most 16 KiB, as an inline chain does.
const EvsStagedSegmentMaxByteCount = EvsInlineMaxByteCount

// One staged segment as checked: its id, its bytes and its header.
type EvsStagedSegment struct {
	Id     [sha256.Size]byte
	Bytes  []byte
	Header *EvsKind5SegmentHeader
}

// A staged segment's bytes held to §11.7's staged row: a kind-5 segment of repoId naming pushId (another push is
// ErrEvsVersioning), at most 16 KiB, of a Padmé length holding its header and a record header.
func EvsStagedSegmentOf(segmentBytes []byte, repoId Id, pushId Id) (*EvsStagedSegment, error) {
	size := uint64(len(segmentBytes))
	if size < EvsKind5SegmentHeaderByteCount+EvsRecordHeaderByteCount || EvsStagedSegmentMaxByteCount < size || !EvsIsPadme(size) {
		return nil, fmt.Errorf("%w: a staged segment of %d bytes", ErrEvsPushInvalid, size)
	}
	header, err := ParseEvsKind5SegmentHeader(segmentBytes)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
	}
	if header.RepoId != repoId {
		return nil, fmt.Errorf("%w: a staged segment of another repo", ErrEvsPushInvalid)
	}
	if header.PushId != pushId {
		return nil, fmt.Errorf("%w: a staged segment naming another push", ErrEvsVersioning)
	}
	return &EvsStagedSegment{Id: sha256.Sum256(segmentBytes), Bytes: segmentBytes, Header: header}, nil
}

// Its new-objects item: kind 2, its id and length, upload day 0.
func (self *EvsStagedSegment) NewObject() *EvsNewObject {
	return &EvsNewObject{
		Kind:       protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT,
		Id:         self.Id[:],
		PaddedSize: uint64(len(self.Bytes)),
	}
}

// The staged bytes of segments: nil when there are none, else a count and each segment's length and bytes.
func EvsEncodeStaged(segments [][]byte) []byte {
	if len(segments) == 0 {
		return nil
	}
	encoded := binary.BigEndian.AppendUint32(nil, uint32(len(segments)))
	return append(encoded, evsJoinItems(segments)...)
}

// The segments staged bytes hold, each bounded as a staged segment is: empty bytes hold none, and a count of 0, an
// item cut short, a count that does not match the items or a segment past 16 KiB is ErrEvsPushInvalid. What each
// segment is, is EvsStagedSegmentOf's.
func EvsDecodeStaged(stagedBytes []byte) ([][]byte, error) {
	if len(stagedBytes) == 0 {
		return nil, nil
	}
	if len(stagedBytes) < 4 {
		return nil, fmt.Errorf("%w: staged bytes of %d", ErrEvsPushInvalid, len(stagedBytes))
	}
	count := binary.BigEndian.Uint32(stagedBytes[:4])
	segments, err := EvsPayloadItems(stagedBytes[4:])
	if err != nil {
		return nil, err
	}
	if count == 0 || uint64(count) != uint64(len(segments)) {
		return nil, fmt.Errorf("%w: a staged count of %d over %d segments", ErrEvsPushInvalid, count, len(segments))
	}
	for _, segment := range segments {
		if EvsStagedSegmentMaxByteCount < len(segment) {
			return nil, fmt.Errorf("%w: a staged segment of %d bytes", ErrEvsPushInvalid, len(segment))
		}
	}
	return segments, nil
}

// Matches staged segments to a push's kind-2 new-objects items, one each and in order (EVS-FORMAT.md): each segment
// checks as EvsStagedSegmentOf does for the push's repo and id, hashes to its item's id and is its item's length.
func evsMatchStaged(push *protocol.EvsPush, newObjects []*EvsNewObject, segments [][]byte) ([]*EvsStagedSegment, error) {
	items := []*EvsNewObject{}
	for _, object := range newObjects {
		if object.Kind == protocol.EvsNewObjectKind_EVS_NEW_OBJECT_STAGED_SEGMENT {
			items = append(items, object)
		}
	}
	if len(items) != len(segments) {
		return nil, fmt.Errorf("%w: %d staged segments for %d staged items", ErrEvsPushInvalid, len(segments), len(items))
	}
	staged := make([]*EvsStagedSegment, len(segments))
	for i, segment := range segments {
		checked, err := EvsStagedSegmentOf(segment, Id(push.GetRepoId()), Id(push.GetPushId()))
		if err != nil {
			return nil, err
		}
		if [sha256.Size]byte(items[i].Id) != checked.Id || items[i].PaddedSize != uint64(len(segment)) {
			return nil, fmt.Errorf("%w: staged segment %d does not hash to its item's id or length", ErrEvsPushInvalid, i)
		}
		staged[i] = checked
	}
	return staged, nil
}
