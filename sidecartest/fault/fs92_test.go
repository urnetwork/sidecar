package fault

// FS-92 on T2 (EVSB-M10-06; owner decision 184; DESIGN-DETAILS 10.2.8's F8): holds and the drop job. A hold covering the
// repo keeps everything the drop would delete while the drop reads done, its stored count falling once, as the held
// objects move to held, and not again when the job deletes them after the hold ends; a sealed hold's answers equal a
// no-hold twin's. The hold placed between verify and the deletes is the same reread (F8) and is held by the deletes'
// own tests; the reads' 404 of held ids is EVS2-M10-10's, unbuilt.

import (
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Places a hold covering the world's network.
func (self *fsDropWorld) placeHold(caseLabel string) {
	self.t.Helper()
	if err := sidecartest.PlaceHold(self.ctx, self.serviceHost.Blobs, &sidecar.HoldRecord{
		NetworkId: self.networkId, CaseId: fsDropId16(caseLabel), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: self.clock.Now(), ExpireTime: self.clock.Now().Add(90 * 24 * time.Hour),
	}); err != nil {
		self.t.Fatal(err)
	}
}

// The drop table's listing, as GET .../drops answers it.
func (self *fsDropWorld) listing() []byte {
	self.t.Helper()
	table, err := evsservice.NewDropTable(self.host.ServiceHost(), evsservice.NewBudgetedBlobs(self.host.Blobs), self.dropSettings, nil)
	if err != nil {
		self.t.Fatal(err)
	}
	read, err := table.Read(self.ctx, self.cluster, self.repoId)
	if err != nil {
		self.t.Fatal(err)
	}
	listing, err := proto.MarshalOptions{Deterministic: true}.Marshal(evsservice.DropStatuses(read.State, read.ReadAt, table.Settings()))
	if err != nil {
		self.t.Fatal(err)
	}
	return listing
}

// FS-92 (a): a hold placed before the DROP: accepted, nothing deleted, the drop reads done, the stored count falling
// once as the objects move to held; once the hold ends the job deletes them, reporting nothing more.
func TestFs92AHoldKeepsWhatTheDropWouldDeleteUntilItEnds(t *testing.T) {
	history := newFs90History(t)
	world := history.world
	world.placeHold("hold case")
	job := world.job("a")
	world.runToEnd(job, 8)
	if state := world.dropState(history.dropId); state != evsservice.DropStateHeld {
		t.Fatalf("drop state %d under a hold", state)
	}
	if !world.stored(history.d1) || !world.stored(history.d2) {
		t.Fatal("a hold's objects were deleted")
	}
	if delta := world.host.Quota.StoredDelta(connect.Id(world.networkId)); delta != -2000 {
		t.Fatalf("stored delta at the hold %d", delta)
	}
	if err := sidecartest.RemoveHold(world.ctx, world.host.Blobs, world.networkId, fsDropId16("hold case")); err != nil {
		t.Fatal(err)
	}
	world.ripen(time.Hour)
	if result := world.runToEnd(job, 8); !result.Ended {
		t.Fatalf("after the hold: %+v", result)
	}
	history.requireDone(t)
}

// FS-92 (c): a sealed hold's answers equal a no-hold twin's: the drop's listing, its state as read and its freed bytes,
// while the twin deletes and the held world keeps.
func TestFs92ASealedHoldsAnswersEqualANoHoldTwin(t *testing.T) {
	held := newFs90History(t)
	held.world.placeHold("sealed case")
	twin := newFs90History(t)
	held.world.runToEnd(held.world.job("a"), 8)
	twin.world.runToEnd(twin.world.job("a"), 8)
	if string(held.world.listing()) != string(twin.world.listing()) {
		t.Fatal("a sealed hold's listing differs from its no-hold twin's")
	}
	if held.world.host.Quota.StoredDelta(connect.Id(held.world.networkId)) != twin.world.host.Quota.StoredDelta(connect.Id(twin.world.networkId)) {
		t.Fatal("a sealed hold's bill differs from its no-hold twin's")
	}
	if !held.world.stored(held.d1) || twin.world.stored(twin.d1) {
		t.Fatal("the twins' stores")
	}
}
