//go:build !sidecar_http && !ios_extension

// A bridge for the directory erasure's tests of QD-1160 (directory_erasure_dropped_test.go), beside QD-1158's
// (directory_erasure_after_cut_export_test.go): another directory admin on both index refs, whose CUTs' set versions
// count; the epoch the set at a ref's head names for an erasure; and an eraser whose CUTs judge which erasures are
// complete by a read of the erasure ref taken before an ERASE opened one of them again.

package sidecar

import (
	"context"
	"slices"
)

// Takes sidecarId as one of the directory's admins on both refs, as another directory admin's device.
func (self *DirectoryErasureTestRefs) Admit(sidecarId Id) {
	for _, ref := range []*directoryErasureTestRef{self.cards, self.streams} {
		ref.world.admins = append(ref.world.admins, sidecarId)
	}
}

// The index_epoch the set at the ref's head names for erasureId's CUT, 0 where it lists none.
func (self *DirectoryErasureTestRefs) ListedEpoch(name string, erasureId Id) uint64 {
	self.t.Helper()
	return indexErasureOf(self.view(self.ref(name)).erasureSet, erasureId).GetEpoch()
}

// The eraser of the ref named name signing as eraserId, as Open, whose CUTs read exactly completeIds complete,
// whatever the erasure ref holds now: CUTs built on a read of it taken before an ERASE opened one of them again.
func (self *DirectoryErasureTestRefs) OpenStale(name string, eraserId Id, completeIds ...Id) DirectoryErasureIndex {
	self.t.Helper()
	index := self.Open(name, eraserId).(*directoryErasureTestRefIndex)
	index.IndexEraser.args.complete = func(ctx context.Context, erasureIds []Id) (map[Id]bool, error) {
		complete := map[Id]bool{}
		for _, erasureId := range erasureIds {
			complete[erasureId] = slices.Contains(completeIds, erasureId)
		}
		return complete, nil
	}
	return index
}
