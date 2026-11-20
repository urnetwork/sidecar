package evsservice

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/sidecartest"
)

// Owner decision 643 (QD-1113; §21.9's expiry row, FI-13c, D-TRUST-7): a 90-day §2703(f) order outlasts the 30 d an
// ended drop's entry is kept. The held job's wakes write the table well past them, and each write keeps the held
// entry, the day it moved to held unchanged, while GET .../drops has let it go as a done drop's would have gone; once
// the order ends the job resumes from that entry, deleting every held id, and its end moves the drop to done and out
// of the table at that write, its 30 d from the move to held long past, so it reads executed: no entry and no void
// record.
func TestDropJobResumesAHoldThatOutlastsTheTablesRetention(t *testing.T) {
	fixture := newDropJobFixture(t)
	world := fixture.world
	fixture.appendDrop("drop-1", world.clock.Now())
	fixture.ripen()
	hold := &sidecar.HoldRecord{
		NetworkId: testId("network-a"), CaseId: testId("case"), Kind: sidecar.HoldKindPreserve2703f,
		Scope: sidecar.HoldScopeNetwork(), PlaceTime: world.clock.Now(), ExpireTime: world.clock.Now().Add(90 * 24 * time.Hour),
	}
	if err := sidecartest.PlaceHold(world.paidCtx, world.host.Blobs, hold); err != nil {
		t.Fatal(err)
	}
	fixture.deleter.held = true
	if result := fixture.run(); result.Waiting != DropWaitHold || fixture.entry("drop-1").State != DropStateHeld {
		t.Fatalf("the held run: %+v", result)
	}
	heldDay := fixture.entry("drop-1").EndedDay
	settings := fixture.job.settings
	retained := dropDayStart(heldDay).Add(settings.EndedRetention + 24*time.Hour)

	// the held job wakes and writes the table every 10 days, to 40 days on: the entry stays
	fixture.deleter.held = false
	for range 4 {
		world.clock.Advance(10 * 24 * time.Hour)
		fixture.hddKnown()
		if result := fixture.run(); result.Waiting != DropWaitHold {
			t.Fatalf("a run under the hold: %+v", result)
		}
	}
	if !retained.Before(world.clock.Now()) {
		t.Fatal("the runs did not pass the held entry's retention")
	}
	if entry := fixture.entry("drop-1"); entry.State != DropStateHeld || entry.EndedDay != heldDay {
		t.Fatalf("the held entry 40 days on: %+v", entry)
	}
	if len(fixture.deleter.requests) != 1 {
		t.Fatalf("%d delete runs under the hold", len(fixture.deleter.requests))
	}
	read, err := fixture.job.Table().Read(world.ctx, world.cluster, world.repoId)
	if err != nil {
		t.Fatal(err)
	}
	if listing := DropStatuses(read.State, read.ReadAt, settings); len(listing.Drops) != 0 {
		t.Fatalf("the listing still names the held drop past its 30 days: %v", listing.Drops)
	}

	// the order ends: the next run takes a round over the held ids, which the table's entry kept
	if err := sidecartest.RemoveHold(world.paidCtx, world.host.Blobs, hold.NetworkId, hold.CaseId); err != nil {
		t.Fatal(err)
	}
	world.clock.AdvanceTo(hold.ExpireTime)
	fixture.horizon.horizon = world.clock.Now()
	fixture.hddKnown()
	result := fixture.run()
	if !result.Ended || result.Moved[DropStateDone] != 1 || len(fixture.deleter.requests) != 2 || len(fixture.deleter.requests[1].Candidates) != 3 {
		t.Fatalf("the run after the hold: %+v, %d delete runs", result, len(fixture.deleter.requests))
	}
	table := fixture.table()
	if table.Drop(testId("drop-1")) != nil || table.Void(testId("drop-1")) != nil || table.Job != nil {
		t.Fatalf("after its deletions the drop stands as %v, its job %+v", dropTestLabels(table), table.Job)
	}
	if liveness := dropLiveness(table, nil); !liveness.Executed(testId("drop-1")) {
		t.Fatal("the drop whose entry left reads live")
	}
}
