// The withheld-id set on the read route (§11.9's serve row, §11.13's delete row; R-ABUSE-5, D-ABUSE-8, FS-92;
// DESIGN-DETAILS 10.2.9's content row; EVS2-M10-10, which EVSB-M10-06's deletes rely on): once a drop job's delete set
// exists, no byte of a segment or slot it deleted, holds or packed is served: a range of such a segment and a read of
// such a slot answer missing, as a deleted object's would, whether or not the object is still stored, so a held drop
// reads as a finished one (owner decision 184) and nothing on the wire shows a hold. The set is the del and held files
// of the repo's running job and of every held job, which gave up the slot to it (QD-1127; DropIndex.Withheld), loaded
// through the table and refreshed with it; a repo with no table, or a table naming no job, pays nothing past the
// table's cached GET. A set that cannot be read fails the read 503.

package evsservice

import (
	"github.com/urnetwork/sidecar"
)

// Whether the read withholds id: see the file header.
func (self *readAttempt) withheld(id DropScanId) (bool, error) {
	if !self.engine.format2Instance() {
		return false, nil
	}
	table, err := self.dropTable()
	if err != nil || table == nil || (table.Job == nil && len(table.HeldJobs) == 0) {
		return false, err
	}
	segmentCluster, err := self.engine.blobs.SegmentCluster()
	if err != nil {
		return false, err
	}
	set, err := self.engine.dropIndex.Withheld(self.ctx, segmentCluster, self.cluster.ClusterId(), self.repoId, table, self.engine.clock.Now())
	if err != nil {
		return false, err
	}
	return set[id], nil
}

// Whether the read withholds the segment.
func (self *readAttempt) withheldSegment(segmentId [32]byte) (bool, error) {
	return self.withheld(DropSegmentId(segmentId))
}

// Whether the read withholds the slot.
func (self *readAttempt) withheldSlot(slotId sidecar.Id) (bool, error) {
	return self.withheld(DropSlotId(slotId))
}
