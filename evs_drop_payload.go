// The DROP payload (§11.6's payload and checks rows, §11.7's action row; EVS-FORMAT.md's DROP pushes): one codec that
// evs's 5c and 5h, the drop job, head readers, replaying readers and the client share, so §11.6 is read once. A DROP's
// statement sets flag 256 alone and drop_sha256, the SHA-256 of its body; its payload's section 9 is the
// EvsDropHistory's bytes, and section 10, per EvsDropPath in paths order, its count listed entry_sha256 values, bare
// 32 B each and strictly ascending, which its listed_sha256 hashes joined. In a push in parts both ride in the parts'
// sections slices, a slice splitting anywhere (plan-EVS2-drop-list-parts), and the seal checks them over the slices
// in part order.
//
// EvsCheckDropPayload is pure: the body is at most 262,144 B on its received length, before any hashing, and hashes to
// drop_sha256 and holds its action's shape (else INVALID); not_before_ms is time_ms + 604,800,000 or time_ms (else
// ErrEvsDropState, 409 DROP_STATE; plan-EVS2-small-readings#2); the paths' counts sum to at most 1,048,576 (QD-700)
// and each list's count, order, repeats and hash hold (else ErrEvsDropList, 409 DROP_LIST). The lists stream through
// a checker that holds one value and one hash at a time, so a check never holds a path's 32 MiB. Kind, path, consent,
// the boundary, the base step 4 read, the fence and a cancel's target need the head, and are evs's (EVS2-M10-09). The
// bounds are EvsFormatSettings' (DESIGN-DETAILS 10.2.2).
//
// On every leg. Package-level functions are safe for concurrent use; an evsDropListChecker is not.

package sidecar

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// §11.7's DROP actions and boundaries (EVS-FORMAT.md); its bounds and window are EvsFormatSettings'.
const (
	evsDropActionDrop      = 1
	evsDropActionCancel    = 2
	evsDropBoundaryWritten = 1
	evsDropBoundaryRemoved = 2
)

var (
	// A DROP list whose count, order, repeats or hash is wrong, or past 2^20: §11.7's 409 DROP_LIST.
	ErrEvsDropList = errors.New("evs drop list refused")
	// A drop whose not_before_ms is neither of its two values: 409 DROP_STATE (plan-EVS2-small-readings#2).
	ErrEvsDropState = errors.New("evs drop state refused")
	// A drop the client cannot form as one DROP push: a body past 256 KiB or lists past 2^20 values in all, which the
	// client's drop engine cuts into several pushes at lineage boundaries, or one lineage that alone passes either
	// bound, or a head-mode walk past its fetch budget (EVS_DROP_TOO_LARGE; DESIGN-DETAILS 10.2.4, QD-700, QD-705).
	ErrEvsDropTooLarge = errors.New("evs: EVS_DROP_TOO_LARGE: a drop past one DROP push's bounds")
)

// A DROP's body and lists as checked: the body's bytes as received, which drop_sha256 covers, and what they parse to.
type EvsCheckedDrop struct {
	Body    []byte
	History *protocol.EvsDropHistory
}

// Whether it is a cancel, action 2.
func (self *EvsCheckedDrop) Cancel() bool {
	return self.History.GetAction() == evsDropActionCancel
}

// §11.6's DROP checks over a push's statement and its sections as received: body, section 9, and the lists, section
// 10, as one slice for a one-part push or one per part in part order. A push without flag 256 carries neither
// section, and one with it carries a body and, for a drop, lists. The body hashes to drop_sha256 and holds its shape,
// else ErrEvsPushInvalid; not_before_ms holds, else ErrEvsDropState; each list holds, else ErrEvsDropList.
func EvsCheckDropPayload(push *protocol.EvsPush, body []byte, listSlices [][]byte) (*EvsCheckedDrop, error) {
	format := DefaultEvsFormatSettings()
	history, err := evsCheckDropBody(format, push, body)
	if err != nil {
		return nil, err
	}
	if history.GetAction() == evsDropActionCancel {
		for _, slice := range listSlices {
			if len(slice) != 0 {
				return nil, fmt.Errorf("%w: a cancel carrying lists", ErrEvsPushInvalid)
			}
		}
		return &EvsCheckedDrop{Body: body, History: history}, nil
	}
	checker, err := newEvsDropListChecker(format, history.GetPaths())
	if err != nil {
		return nil, err
	}
	for _, slice := range listSlices {
		if err := checker.write(slice); err != nil {
			return nil, err
		}
	}
	if err := checker.close(); err != nil {
		return nil, err
	}
	return &EvsCheckedDrop{Body: body, History: history}, nil
}

// The DROP sections of a format-2 push as the payload checks meet them: none on a push without flag 256, else
// EvsCheckDropPayload's.
func evsCheckDropSlices(statement *EvsStatement, body []byte, listSlices [][]byte) (*EvsCheckedDrop, error) {
	push := statement.Push
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 {
		if len(body) != 0 {
			return nil, fmt.Errorf("%w: a DROP body without flag 256", ErrEvsPushInvalid)
		}
		for _, slice := range listSlices {
			if len(slice) != 0 {
				return nil, fmt.Errorf("%w: DROP lists without flag 256", ErrEvsPushInvalid)
			}
		}
		return nil, nil
	}
	return EvsCheckDropPayload(push, body, listSlices)
}

// The body's bytes held to their bound before any hashing, then to drop_sha256 and to its action's shape, and
// not_before_ms to its two values.
func evsCheckDropBody(format *EvsFormatSettings, push *protocol.EvsPush, body []byte) (*protocol.EvsDropHistory, error) {
	if push.GetFlags()&uint32(protocol.EvsPushFlag_EVS_PUSH_DROP) == 0 || len(push.GetDropSha256()) != sha256.Size {
		return nil, fmt.Errorf("%w: a DROP body under a statement with no flag 256 or drop_sha256", ErrEvsPushInvalid)
	}
	if format.DropMaxBodyByteCount < len(body) {
		// on the received length, before any hashing (DESIGN-DETAILS 10.2.2's body row)
		return nil, fmt.Errorf("%w: a DROP body of %d bytes, past %d", ErrEvsPushInvalid, len(body), format.DropMaxBodyByteCount)
	}
	digest := sha256.Sum256(body)
	if len(body) == 0 || !bytes.Equal(digest[:], push.GetDropSha256()) {
		return nil, fmt.Errorf("%w: the DROP body does not match drop_sha256", ErrEvsPushInvalid)
	}
	history := &protocol.EvsDropHistory{}
	if err := proto.Unmarshal(body, history); err != nil {
		return nil, fmt.Errorf("%w: a DROP body that does not parse", ErrEvsPushInvalid)
	}
	if err := checkEvsDropHistoryShape(format, history, push.GetPathEpoch()); err != nil {
		return nil, err
	}
	if history.GetAction() == evsDropActionDrop {
		notBeforeMs := history.GetNotBeforeMs()
		if notBeforeMs != push.GetTimeMs() && notBeforeMs != push.GetTimeMs()+format.DropWindowMs() {
			return nil, fmt.Errorf("%w: not_before_ms %d for a statement of %d", ErrEvsDropState, notBeforeMs, push.GetTimeMs())
		}
	}
	return history, nil
}

// An EvsDropHistory's shape (EVS-FORMAT.md): a 16 B drop_id; a drop with 1 to 1,024 paths strictly ascending by their
// newest lineage entry's token path, then epoch, a preview id of 16 B or none, and no cancel field; a cancel with a
// 16 B cancels_drop_id, a cancels_version, and no path, not_before_ms or preview id; each path's lineage newest first,
// epochs strictly descending from at most pathEpoch to at least 1, a map part per older entry, a through_version of at
// least 2, boundary 1 or 2 and a 32 B listed_sha256. A count off its bounds is the list's, ErrEvsDropList.
func checkEvsDropHistoryShape(format *EvsFormatSettings, history *protocol.EvsDropHistory, pathEpoch uint64) error {
	if len(history.GetDropId()) != 16 {
		return fmt.Errorf("%w: a drop_id of %d bytes", ErrEvsPushInvalid, len(history.GetDropId()))
	}
	switch history.GetAction() {
	case evsDropActionDrop:
		if len(history.GetCancelsDropId()) != 0 || history.GetCancelsVersion() != 0 {
			return fmt.Errorf("%w: a drop naming a drop it cancels", ErrEvsPushInvalid)
		}
		if previewId := history.GetPreviewId(); len(previewId) != 0 && len(previewId) != 16 {
			return fmt.Errorf("%w: a preview_id of %d bytes", ErrEvsPushInvalid, len(previewId))
		}
		paths := history.GetPaths()
		if len(paths) == 0 || format.DropMaxPathCount < len(paths) {
			return fmt.Errorf("%w: a drop of %d paths", ErrEvsPushInvalid, len(paths))
		}
		var previous *protocol.EvsSourcePath
		for _, path := range paths {
			if err := checkEvsDropPathShape(path, pathEpoch); err != nil {
				return err
			}
			newest := path.GetLineage()[0]
			if previous != nil && 0 <= evsCompareDropLineageEntries(previous, newest) {
				return fmt.Errorf("%w: a drop's paths not strictly ascending by their newest token path", ErrEvsPushInvalid)
			}
			previous = newest
		}
	case evsDropActionCancel:
		if len(history.GetCancelsDropId()) != 16 || history.GetCancelsVersion() == 0 {
			return fmt.Errorf("%w: a cancel naming no drop", ErrEvsPushInvalid)
		}
		if len(history.GetPaths()) != 0 || history.GetNotBeforeMs() != 0 || len(history.GetPreviewId()) != 0 {
			return fmt.Errorf("%w: a cancel carrying paths, a not_before_ms or a preview", ErrEvsPushInvalid)
		}
	default:
		return fmt.Errorf("%w: DROP action %d", ErrEvsPushInvalid, history.GetAction())
	}
	return nil
}

// One lineage's shape: its entries, map parts, through_version, boundary and list hash; its count's bounds are the
// list's.
func checkEvsDropPathShape(path *protocol.EvsDropPath, pathEpoch uint64) error {
	lineage := path.GetLineage()
	if len(lineage) == 0 || len(path.GetMapParts()) != len(lineage)-1 {
		return fmt.Errorf("%w: a lineage of %d entries with %d map parts", ErrEvsPushInvalid, len(lineage), len(path.GetMapParts()))
	}
	for i, entry := range lineage {
		if entry.GetEpoch() == 0 || (i == 0 && pathEpoch < entry.GetEpoch()) || (0 < i && lineage[i-1].GetEpoch() <= entry.GetEpoch()) {
			return fmt.Errorf("%w: a lineage entry of epoch %d", ErrEvsPushInvalid, entry.GetEpoch())
		}
		if _, err := ParseEvsChangedTokenPath(entry.GetTokenPath()); err != nil {
			return fmt.Errorf("%w: %w", ErrEvsPushInvalid, err)
		}
	}
	if path.GetThroughVersion() < 2 {
		return fmt.Errorf("%w: a through_version of %d keeps no version above a listed one", ErrEvsPushInvalid, path.GetThroughVersion())
	}
	if path.GetBoundary() != evsDropBoundaryWritten && path.GetBoundary() != evsDropBoundaryRemoved {
		return fmt.Errorf("%w: boundary %d", ErrEvsPushInvalid, path.GetBoundary())
	}
	if len(path.GetListedSha256()) != sha256.Size {
		return fmt.Errorf("%w: a listed_sha256 of %d bytes", ErrEvsPushInvalid, len(path.GetListedSha256()))
	}
	return nil
}

// The order of two lineage entries: their token paths' bytes, then their epochs.
func evsCompareDropLineageEntries(a *protocol.EvsSourcePath, b *protocol.EvsSourcePath) int {
	if order := bytes.Compare(bytes.Join(a.GetTokenPath(), nil), bytes.Join(b.GetTokenPath(), nil)); order != 0 {
		return order
	}
	switch {
	case a.GetEpoch() < b.GetEpoch():
		return -1
	case b.GetEpoch() < a.GetEpoch():
		return 1
	}
	return 0
}

// Streams a drop's lists, section 10, in slices split anywhere: per path in order, its count values, each strictly
// above the one before, hashing to its listed_sha256. It holds one partial value and one hash.
type evsDropListChecker struct {
	format *EvsFormatSettings
	paths  []*protocol.EvsDropPath
	// the path whose values come next, and how many it has left
	path      int
	remaining uint32
	previous  [sha256.Size]byte
	// whether previous holds a value of the current path
	started bool
	digest  hash.Hash
	// a value split across slices
	pending []byte
}

// A checker of paths' lists, before its first value: ErrEvsDropList when their counts sum past
// DropMaxListedCount (QD-700), which no list byte is read to find.
func newEvsDropListChecker(format *EvsFormatSettings, paths []*protocol.EvsDropPath) (*evsDropListChecker, error) {
	total := uint64(0)
	for _, path := range paths {
		total += uint64(path.GetCount())
	}
	if uint64(format.DropMaxListedCount) < total {
		return nil, fmt.Errorf("%w: %d listed versions in all, past %d", ErrEvsDropList, total, format.DropMaxListedCount)
	}
	return &evsDropListChecker{format: format, paths: paths, path: -1, digest: sha256.New(), pending: make([]byte, 0, sha256.Size)}, nil
}

// Moves to the next path, checking its count's bounds.
func (self *evsDropListChecker) nextPath() error {
	self.path += 1
	if len(self.paths) <= self.path {
		return nil
	}
	path := self.paths[self.path]
	if path.GetCount() == 0 || uint64(self.format.DropMaxListedCount) < uint64(path.GetCount()) || path.GetThroughVersion() <= uint64(path.GetCount()) {
		return fmt.Errorf("%w: path %d lists %d versions below %d", ErrEvsDropList, self.path, path.GetCount(), path.GetThroughVersion())
	}
	self.remaining = path.GetCount()
	self.started = false
	self.digest.Reset()
	return nil
}

// Takes one listed value of the current path.
func (self *evsDropListChecker) value(value []byte) error {
	if self.path < 0 {
		if err := self.nextPath(); err != nil {
			return err
		}
	}
	if len(self.paths) <= self.path {
		return fmt.Errorf("%w: a value past the last path's count", ErrEvsDropList)
	}
	if self.started && bytes.Compare(self.previous[:], value) >= 0 {
		return fmt.Errorf("%w: path %d's list out of order or repeating", ErrEvsDropList, self.path)
	}
	copy(self.previous[:], value)
	self.started = true
	self.digest.Write(value)
	self.remaining -= 1
	if self.remaining == 0 {
		if !bytes.Equal(self.digest.Sum(nil), self.paths[self.path].GetListedSha256()) {
			return fmt.Errorf("%w: path %d's list does not match its listed_sha256", ErrEvsDropList, self.path)
		}
		return self.nextPath()
	}
	return nil
}

// Takes the next slice of the lists.
func (self *evsDropListChecker) write(slice []byte) error {
	for 0 < len(slice) {
		if len(self.pending) != 0 || len(slice) < sha256.Size {
			take := min(sha256.Size-len(self.pending), len(slice))
			self.pending = append(self.pending, slice[:take]...)
			slice = slice[take:]
			if len(self.pending) == sha256.Size {
				if err := self.value(self.pending); err != nil {
					return err
				}
				self.pending = self.pending[:0]
			}
			continue
		}
		if err := self.value(slice[:sha256.Size]); err != nil {
			return err
		}
		slice = slice[sha256.Size:]
	}
	return nil
}

// Ends the lists: no value cut short, and every path's count met.
func (self *evsDropListChecker) close() error {
	if len(self.pending) != 0 {
		return fmt.Errorf("%w: the lists end inside a value", ErrEvsDropList)
	}
	if self.path < 0 {
		if err := self.nextPath(); err != nil {
			return err
		}
	}
	if self.path < len(self.paths) {
		return fmt.Errorf("%w: path %d's list ends %d values short", ErrEvsDropList, self.path, self.remaining)
	}
	return nil
}

// A drop's lists for the paths given, as the client builds section 10: each path's entry hashes sorted ascending, and
// each path's count and listed_sha256 set from them. Repeats are refused, since a list holds each version once.
func EvsBuildDropLists(paths []*protocol.EvsDropPath, listed [][][]byte) ([]byte, error) {
	if len(paths) != len(listed) {
		return nil, fmt.Errorf("%w: %d lists for %d paths", ErrEvsDropList, len(listed), len(paths))
	}
	lists := []byte{}
	for i, path := range paths {
		values := make([][]byte, len(listed[i]))
		copy(values, listed[i])
		for _, value := range values {
			if len(value) != sha256.Size {
				return nil, fmt.Errorf("%w: a listed value of %d bytes", ErrEvsDropList, len(value))
			}
		}
		slices.SortFunc(values, bytes.Compare)
		digest := sha256.New()
		for j, value := range values {
			if 0 < j && bytes.Equal(values[j-1], value) {
				return nil, fmt.Errorf("%w: a version listed twice", ErrEvsDropList)
			}
			digest.Write(value)
			lists = append(lists, value...)
		}
		path.Count = uint32(len(values))
		path.ListedSha256 = digest.Sum(nil)
	}
	return lists, nil
}
