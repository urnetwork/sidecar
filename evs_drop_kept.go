//go:build !ios_extension

// A DROP's kept head (§11.7's boundary, why and checkpoint rows, rule (5); FS-89, FS-95; EVS2-M10-21): a written
// lineage's change writes through_version, the path's next version, with the head's plaintext, mode and git oid, at
// versioning 0.
//
//	small    up to 8 MiB, one checkpoint under a fresh object key: an upload, or inline when it pads to at most 16 KiB,
//	         and in a slot-keyed repo a new slot. A head whose chain holds diffs gets one too, since those records
//	         are older versions' content and citing them would keep listed versions reconstructable
//	chunked  above 8 MiB the head's chunk set cited as it stands: chunk records hold only the head's bytes, so they
//	         are cited, all but the last a whole 4 MiB chunk; a REMOVE generation newer than their key re-encrypts
//	         them, as checkpoint rule (4) has any write do, which evs takes as this push's uploads
//	refused  a versionless head, which a drop cannot keep (turn versioning on first; §11.7's refused row, VERSIONING
//	         at evs); a head that moved since the dry run, or whose version is not the one through_version follows
//	         (ErrEvsDropStale)
//
// The head's plaintext is read whole into the client's spill, which goes to the sealed store past its memory bound,
// so a large head is streamed, never held. Each write is held to the version its content came from (IfBaseVersion),
// so a write that landed meanwhile fails the push.
//
// On every leg but ios_extension.

package sidecar

import (
	"context"
	"errors"
	"fmt"

	"github.com/urnetwork/sidecar/protocol"
)

// A drop of a versionless head, which keeps no older version to drop or keep (VERSIONING at evs).
var ErrEvsDropVersionless = errors.New("evs: a drop of a versionless file: turn its versioning on first")

// The kept heads of lineages' written boundaries, and what closes their content.
func (self *EvsRepo) dropKeptWrites(ctx context.Context, refName []byte, lineages []*EvsDropLineage) ([]*EvsPathWrite, func(), error) {
	spills := []*evsSpill{}
	closeAll := func() {
		for _, spill := range spills {
			spill.close()
		}
	}
	writes := []*EvsPathWrite{}
	for _, lineage := range lineages {
		if lineage.DropPath.GetBoundary() != EvsDropBoundaryWritten {
			continue
		}
		if len(lineage.Versions) == 0 || lineage.Versions[0].Removed {
			closeAll()
			return nil, nil, fmt.Errorf("%w: a written boundary over no standing version", ErrEvsDropStale)
		}
		newest := lineage.Versions[0]
		if newest.Versioning != uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT) {
			closeAll()
			return nil, nil, ErrEvsDropVersionless
		}
		if newest.Version+1 != lineage.DropPath.GetThroughVersion() {
			closeAll()
			return nil, nil, fmt.Errorf("%w: a kept version that is not the head's next", ErrEvsDropStale)
		}
		spill := newEvsSpill(self.client.args.Store, self.client.settings.DeltaBaseMemoryByteCount)
		spills = append(spills, spill)
		info, err := self.ReadHead(ctx, &EvsReadArgs{RefName: refName, Path: lineage.Path, Fresh: true}, spill)
		if err != nil {
			closeAll()
			return nil, nil, err
		}
		if info.Version != newest.Version {
			closeAll()
			return nil, nil, fmt.Errorf("%w: the head is at version %d, the dry run's at %d", ErrEvsDropStale, info.Version, newest.Version)
		}
		base := newest.Version
		writes = append(writes, &EvsPathWrite{
			Path: lineage.Path, Content: spill, Mode: info.Mode, IfBaseVersion: &base,
			// one fresh checkpoint up to 8 MiB; above it the chunk set cited as it stands
			ForceCheckpoint: !EvsChunked(uint64(spill.Size())),
			Versioning:      uint32(protocol.EvsVersioning_EVS_VERSIONING_KEPT),
		})
	}
	return writes, closeAll, nil
}
