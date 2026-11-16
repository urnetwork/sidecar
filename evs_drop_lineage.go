//go:build !ios_extension

// A drop's lineage and list (§11.7's cli row; R-EVS-26, D-EVS-62, FI-27, FS-89, FS-93; DESIGN-DETAILS 10.2.4 with 10.7's
// amended item; EVS2-M10-20). A lineage is one path name on a ref as far as evs can follow it: its token path per path
// epoch, newest first, from the oldest epoch a walked version's statement declares up to the ref's current epoch for a
// path that stands, or the epoch its removal committed in for one that is removed. The list is every version of those
// token paths that has an entry, below through_version, by entry hash, ascending (plan-EVS2-small-readings#1: a
// removal has no entry and is never listed).
//
//	versions   the path's versions, newest first, from History's verified walk (evs_drop_list.go), every one checked
//	           as §11.9's reader row checks a version; a removed earlier life in the same epoch shares the token path
//	           and is walked too, while one removed before a cut-over and re-created after is another lineage, never
//	           joined
//	boundary   1 written for a path that stands: through_version is its newest version + 1, which the DROP writes; 2
//	           removed for one that is removed: through_version is its standing removal's version
//	refused    by name, here, since evs cannot see them (plan-EVS2-drop-path-visibility): the ur/index and ur/lfs refs,
//	           a path under .ur-index/, and a directory; ErrEvsDropPath
//	bounds     one lineage whose body passes DropMaxBodyByteCount, or whose list passes DropMaxListedCount, is refused
//	           locally (ErrEvsDropTooLarge, QD-700); a head-mode device walks within HeadDropFetchByteCount, counted at
//	           a statement's bound a version, past which it answers ErrEvsDropTooLarge naming `ur history drop` on a
//	           device that mirrors the repo (QD-705)
//	prefix     in a repo with prefix rule sets the builder reads the path with 16.2.5's effective and builds only over
//	           a newest event it allows; one it cannot judge (a set pending or newer, a walk ending in depth or
//	           unavailable) stops with that answer; one it ignores is written back first by the repair form with no
//	           edit (EvsRepo.RepairPath), on a device that mirrors the ref and is allowed the path, and the lineage is
//	           built on the head that push left, so the list takes the ignored versions; any other device stops with
//	           EVS_PREFIX_RULE detail refused, naming `ur evs repair` on a device that mirrors the ref. The repair and
//	           the DROP never share a push
//
// map_parts is the one field taken from evs, from the dry run (evs_drop_preview.go); until then each older entry's is 0.
// A lineage entry the builder includes that no committed map links answers linked false at the dry run, which stops
// the command: the epochs come from the walked versions and the current one, and an epoch the ref passed through with
// no version of the path in it is not walked here (incomplete; the dry run fails closed on it). The plaintext path
// stays on the device (I-13).
//
// On every leg but ios_extension. Safe for concurrent use.

package sidecar

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/sidecar/protocol"
)

// A DROP's boundaries (§11.6's EvsDropPath.boundary).
const (
	EvsDropBoundaryWritten = 1
	EvsDropBoundaryRemoved = 2
)

var (
	// A path a drop cannot name, refused by name before anything is sent: a reserved ref, the index's root, a
	// directory (EVS_DROP_PATH).
	ErrEvsDropPath = errors.New("evs: EVS_DROP_PATH: a path a drop cannot name")
	// The dry run's resolved list differs from the builder's: the command stops, nothing signed.
	ErrEvsDropListMismatch = errors.New("evs: a drop's list does not match the ref's history")
	// The dry run found an older lineage entry no committed map or tail links: the command stops.
	ErrEvsDropUnlinked = errors.New("evs: a drop's lineage that evs cannot follow")
)

// One path's lineage and list, as a DROP and its dry run carry them.
type EvsDropLineage struct {
	Path string
	// The lineage newest first, map_parts (the dry run's, zeros before it), through_version, boundary, count and
	// listed_sha256.
	DropPath *protocol.EvsDropPath
	// The listed entry hashes, ascending.
	Listed [][]byte
	// The versions walked, newest first, removals included.
	Versions []*EvsHistoryVersion
}

// The lineage of path on the ref refName: see the file header.
func (self *EvsRepo) DropLineage(ctx context.Context, refName []byte, path string) (*EvsDropLineage, error) {
	if refName == nil {
		refName = EvsMainRefName
	}
	names, err := evsDropPathNames(refName, path)
	if err != nil {
		return nil, err
	}
	refId, err := self.resolveRefId(ctx, refName, nil)
	if err != nil {
		return nil, err
	}
	if err := self.dropPrefixRules(ctx, refName, refId, path); err != nil {
		return nil, err
	}
	if err := self.dropRefuseDirectory(ctx, refId, path); err != nil {
		return nil, err
	}
	walk, err := self.dropWalk(ctx, refName, path)
	if err != nil {
		return nil, err
	}
	if len(walk.versions) == 0 {
		return nil, ErrEvsPathAbsent
	}
	newest := walk.versions[0]
	dropPath := &protocol.EvsDropPath{}
	lineageEpochs := map[uint64]bool{}
	for _, version := range walk.versions {
		lineageEpochs[version.Epoch] = true
	}
	if newest.Removed {
		dropPath.Boundary, dropPath.ThroughVersion = EvsDropBoundaryRemoved, newest.Version
	} else {
		dropPath.Boundary, dropPath.ThroughVersion = EvsDropBoundaryWritten, newest.Version+1
		state, err := self.freshEpochState(ctx, refId)
		if err != nil {
			return nil, err
		}
		lineageEpochs[state.epoch.GetCurrent()] = true
	}
	epochs := make([]uint64, 0, len(lineageEpochs))
	for epoch := range lineageEpochs {
		epochs = append(epochs, epoch)
	}
	slices.Sort(epochs)
	slices.Reverse(epochs)
	keys := newEvsReadKeys(self)
	for _, epoch := range epochs {
		tokenPath, err := keys.tokenPathIn(ctx, names, epoch)
		if err != nil {
			return nil, err
		}
		dropPath.Lineage = append(dropPath.Lineage, &protocol.EvsSourcePath{Epoch: epoch, TokenPath: tokenPath.Components()})
	}
	dropPath.MapParts = make([]uint32, len(dropPath.Lineage)-1)
	listed := [][]byte{}
	for _, version := range walk.versions {
		if version.Removed || len(version.EntrySha256) == 0 {
			continue
		}
		if dropPath.ThroughVersion <= version.Version {
			return nil, fmt.Errorf("%w: a walked version at or past the one the drop keeps", ErrEvsReplyInvalid)
		}
		listed = append(listed, bytes.Clone(version.EntrySha256))
	}
	format := DefaultEvsFormatSettings()
	if len(listed) == 0 {
		return nil, fmt.Errorf("%w: the path has no older version to drop", ErrEvsDropPath)
	}
	if format.DropMaxListedCount < len(listed) {
		return nil, fmt.Errorf("%w: one lineage of %d versions, past %d", ErrEvsDropTooLarge, len(listed), format.DropMaxListedCount)
	}
	if _, err := EvsBuildDropLists([]*protocol.EvsDropPath{dropPath}, [][][]byte{listed}); err != nil {
		return nil, err
	}
	slices.SortFunc(listed, bytes.Compare)
	if format.DropMaxBodyByteCount < proto.Size(dropPath) {
		return nil, fmt.Errorf("%w: one lineage of %d body bytes, past %d", ErrEvsDropTooLarge, proto.Size(dropPath), format.DropMaxBodyByteCount)
	}
	return &EvsDropLineage{Path: path, DropPath: dropPath, Listed: listed, Versions: walk.versions}, nil
}

// The names of a path a drop may name on refName, else ErrEvsDropPath: no reserved ref, nothing under the index's root.
func evsDropPathNames(refName []byte, path string) ([][]byte, error) {
	for _, reserved := range evsReservedRefNames {
		if bytes.Equal(refName, reserved) {
			return nil, fmt.Errorf("%w: a reserved ref", ErrEvsDropPath)
		}
	}
	names, err := evsPathNames(path)
	if err != nil {
		return nil, err
	}
	if bytes.Equal(names[0], evsReservedIndexDirectory) {
		return nil, fmt.Errorf("%w: under the index's root", ErrEvsDropPath)
	}
	return names, nil
}

// Refuses a directory by name: evs keeps no versions of its rows a drop could list.
func (self *EvsRepo) dropRefuseDirectory(ctx context.Context, refId Id, path string) error {
	result, err := self.read(ctx, refId, []string{path}, 0, true)
	if err != nil {
		return err
	}
	defer result.objects.close()
	verified := result.replies[0]
	if verified.Entry != nil && verified.Entry.GetKind() == uint32(protocol.EvsEntryKind_EVS_ENTRY_DIRECTORY) {
		return fmt.Errorf("%w: a directory", ErrEvsDropPath)
	}
	return nil
}

// 10.2.4's prefix rules row: see the file header.
func (self *EvsRepo) dropPrefixRules(ctx context.Context, refName []byte, refId Id, path string) error {
	ruled, err := self.prefixRuled()
	if err != nil || ruled == nil {
		return err
	}
	result, err := self.read(ctx, refId, []string{path}, 0, true)
	if err != nil {
		return err
	}
	shown, read, err := ruled.effective(ctx, self, path, result)
	if err != nil {
		return err
	}
	shown.objects.close()
	if read.ignoredAbove == 0 {
		return nil
	}
	// the newest event is one this device ignores: the effective state written back first, by its own push
	if _, err := self.RepairPath(ctx, refName, path); err != nil {
		if errors.Is(err, ErrEvsPrefixRepairOff) {
			return fmt.Errorf("%w: run ur evs repair on a device that mirrors the ref, then drop", &EvsPrefixRuleError{Detail: EvsPrefixDetailRefused, Path: path})
		}
		return err
	}
	return nil
}
