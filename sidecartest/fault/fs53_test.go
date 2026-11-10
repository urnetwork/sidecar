package fault

// FS-53 (§22.8, FI-1; owner decision 136; EVSB-M2-11) on T2: a config repo with under 256 KiB of aged history. Its
// records go to a parcel on NVMe at 25 h, each hourly run that finds some, and to one pack on the segment cluster
// once the oldest would pass 7 d, the parcels and their entries deleted behind it. Reads verify at each step: a
// reader with no cache finds every committed record's bytes as its batch held them (fs60_test.go's world).
//
// The repo here keeps writing, so the run that evacuates it packs it. An idle repo's 7 d pack is the nightly
// pass's, EVSB-M2-12's.

import (
	"testing"
	"time"

	"github.com/urnetwork/sidecar/protocol"
)

func TestFs53ConfigRepoGoesToParcelsAtTwentyFiveHoursAndPacksAtSevenDays(t *testing.T) {
	world := newEvacuationWorld(t)
	world.repoKind = protocol.RepoKind_REPO_KIND_CONFIG
	world.putRepo(protocol.EvsRepoState_EVS_REPO_ACTIVE)
	start := world.clock.Now()

	// a statement or two a day: each is in its batch for 25 h, then in a parcel
	for day := 0; day < 5; day += 1 {
		world.clock.AdvanceTo(start.Add(time.Duration(day) * 24 * time.Hour))
		world.commit()
		world.commit()
		world.requireEveryRecord("in their batches")
		world.clock.Advance(24*time.Hour + 30*time.Minute)
		early := world.mustRun()
		if early.KeptCount != 0 || len(world.keys("meta-1", "pb/")) != 2 {
			t.Fatalf("day %d: a batch under 25 h old was taken: %+v", day, early)
		}
		world.clock.Advance(32 * time.Minute)
		result := world.mustRun()
		if result.KeptCount != 2 || result.ParcelCount != 1 || result.PackCount != 0 || result.HasBatches {
			t.Fatalf("day %d: %+v", day, result)
		}
		if parcels := world.keys("meta-1", "hp/"); len(parcels) != day+1 {
			t.Fatalf("day %d: parcels %v", day, parcels)
		}
		world.requireEveryRecord("in parcels")
	}
	if packs := world.keys("seg-1", "pack/"); len(packs) != 0 {
		t.Fatalf("a pack before 7 d: %v", packs)
	}

	// the write whose evacuation comes as the first record nears 7 d takes every parcel into one pack
	world.clock.AdvanceTo(start.Add(7*24*time.Hour - 26*time.Hour))
	world.commit()
	world.age()
	result := world.mustRun()
	if result.PackCount != 1 || result.ReplacedParcelCount != 5 || result.ParcelCount != 0 || result.HasBatches {
		t.Fatalf("the 7 d run: %+v", result)
	}
	if age := world.clock.Now().Sub(start); 7*24*time.Hour < age {
		t.Fatalf("the pack came %s after the first record, past 7 d", age)
	}
	if left := world.keys("meta-1", "hp/"); len(left) != 0 {
		t.Fatalf("parcels left on NVMe: %v", left)
	}
	if packs, entries := world.keys("seg-1", "pack/"), world.keys("meta-1", "pidx/"); len(packs) != 1 || len(entries) != 1 {
		t.Fatalf("packs %v, entries %v", packs, entries)
	}
	world.requireEveryRecord("in the pack")

	// later history starts a new parcel
	world.commit()
	world.age()
	if result := world.mustRun(); result.ParcelCount != 1 || result.PackCount != 0 {
		t.Fatalf("after the pack: %+v", result)
	}
	world.requireEveryRecord("after the pack")
}
