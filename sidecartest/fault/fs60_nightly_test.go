package fault

// FS-60's nightly clauses (§22.8, FI-1, FI-13 (c); EVSB-M2-12), on T2: the nightly pass over the evacuation world of
// fs60_test.go. A small repo no push brings back to evacuation has its parcels packed by the pass as they near 7 d,
// the replacement killed between the pack's entries and the parcel's delete and finished by the next night, a
// reader finding every record at each step and taking the pack's entry over the parcel's; and the pass's count is
// the LIST sizes plus the batch-resident record lengths, less the containers it deleted. T3's run on the real store
// is EVSB-M2-17's suite.

import (
	"context"
	"testing"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// One nightly run of meta-1's one shard, the segment cluster quiet.
func (self *evacuationWorld) nightly() (*evsservice.NightlyResult, error) {
	self.t.Helper()
	pass, err := evsservice.NewNightlyPass(self.host.ServiceHost(), &evsservice.NightlyPassDeps{
		Evacuator:          self.settings,
		SegmentClusterBusy: func(ctx context.Context, clusterId string) bool { return false },
	})
	if err != nil {
		self.t.Fatal(err)
	}
	return pass.Run(self.ctx, "meta-1", "", "")
}

// FS-60: a small repo's parcels pack at 7 d in the nightly pass when no push brings the repo back to evacuation,
// the replacement killed between the pack's entries and the parcel's delete; a reader finds every record
// throughout, and the next night deletes the parcel the pack holds.
func TestFs60NightlyPacksAnIdleRepoWithTheReplacementKilled(t *testing.T) {
	world := newEvacuationWorld(t)
	world.commit()
	world.age()
	if result := world.mustRun(); result.ParcelCount != 1 {
		t.Fatalf("evacuation %+v", result)
	}
	parcels := world.keys("meta-1", "hp/")

	// the night its parcel's oldest record would pass 7 d before the next night
	world.clock.Advance(5*24*time.Hour + time.Hour)
	world.killAt(sidecartest.FaultOpDelete, "pidx/", 1)
	if result, err := world.nightly(); err == nil {
		t.Fatalf("the pass was not killed: %+v", result)
	}
	if unfired := world.host.Blobs.Faults().Unfired(); len(unfired) != 0 {
		t.Fatalf("the kill never fired: %v", unfired)
	}
	if packs := world.keys("seg-1", "pack/"); len(packs) != 1 {
		t.Fatalf("packs after the kill: %v", packs)
	}
	if kept := world.keys("meta-1", "hp/"); len(kept) != 1 || kept[0] != parcels[0] {
		t.Fatalf("the parcel went past the kill: %v", kept)
	}
	world.requireEveryRecord("the pack and the parcel both standing")

	world.clock.Advance(24 * time.Hour)
	result, err := world.nightly()
	if err != nil {
		t.Fatalf("the next night: %v (%+v)", err, result)
	}
	if result.IdlePackCount != 0 || result.ReplacedParcelCount != 1 {
		t.Fatalf("the next night %+v", result)
	}
	if left := world.keys("meta-1", "hp/"); len(left) != 0 {
		t.Fatalf("parcels left: %v", left)
	}
	world.requireEveryRecord("after the parcel went")
}

// FI-13 (c) after a pass: the network's count is what the LISTs show of seg/, pack/ and hp/ plus the lengths the
// head window gives for records still in batches, and a container the pass deleted counts no more.
func TestFs60NightlyCountIsListSizesPlusBatchRecords(t *testing.T) {
	world := newEvacuationWorld(t)
	first := world.commit()
	world.age()
	world.mustRun()
	second := world.commit()

	result, err := world.nightly()
	if err != nil {
		t.Fatal(err)
	}
	stored := result.NetworkBytes[world.networkId]
	if stored == nil {
		t.Fatalf("no count for the network: %+v", result)
	}
	listed := int64(0)
	for _, family := range []struct{ clusterId, prefix string }{{"seg-1", "seg/"}, {"seg-1", "pack/"}, {"meta-1", "hp/"}} {
		cluster, err := world.host.Blobs.Cluster(family.clusterId)
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range world.keys(family.clusterId, family.prefix) {
			info, err := cluster.Head(sidecartest.InspectContext(world.ctx), key)
			if err != nil {
				t.Fatal(err)
			}
			listed += info.ByteCount
		}
	}
	if want := listed + int64(second.place.GetLength()); stored.StoredByteCount() != want {
		t.Fatalf("count %d (%+v), want %d: listed %d and the batch-resident record's %d", stored.StoredByteCount(), stored, want, listed, second.place.GetLength())
	}
	if stored.BatchRecordByteCount != int64(second.place.GetLength()) || first.place.GetLength() == 0 {
		t.Fatalf("batch-resident %d", stored.BatchRecordByteCount)
	}
}
