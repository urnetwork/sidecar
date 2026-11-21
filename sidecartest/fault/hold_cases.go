// The hold cases of FS-69, FS-66 and FS-6 (§22.8; §11.12's shred row, §11.13's purge, staged, sweep and holds rows,
// §21.9's preservation holds, owner decisions 133, 184 and 629, FI-5, FI-16; ABUSE-M10-01) on the evs world, each hold
// placed and ended through its Net's api (EvsWorldHolds, fs92_hold.go: server's api on T3, the fixture on T2) beside a
// twin that places none. Every hold here is a 90-day §2703(f) order, ended by api's hold pass at its deadline.
//
//	FS-69     Fs69HoldBeforeAReplacement, the registered case, a general repo with purge on: p.bin written versionless,
//	          a kind-5 segment, then the hold, then p.bin replaced twice. A day on, evacuation's sweep keeps the first
//	          version's segment, which existed at the placement, and purges the second's, written and replaced under
//	          the hold. api's pass ends the hold, its hold-end sweep runs as taskworker runs evs.sweep, and the held
//	          segment goes; the newest version reads whole throughout. The twin, Fs69NoHold, purges both at once.
//	          Fs69HoldBetweenSweepDeletes: two files replaced before the hold, the sweep held after its first DELETE, the
//	          hold placed and the clock moved past §11.13's 5 s cache: that DELETE stands, and the second, which existed
//	          at the placement, is kept by the reread. Fs69EraseUnderTheHold, a record repo: an ERASE of a versionless
//	          entry's keys under the hold destroys them at once. Its newest version reads erased while the ciphertext stays
//	FS-66     Fs66HoldKeepsStagedFromBeforeIt, the registered hold case: h.txt written versionless and staged, then the
//	          hold, then h.txt replaced twice, each in a batch of its own. At evacuation the first version's staged
//	          segment, from a batch before the placement, is written to seg/, the second's, written and replaced under
//	          the hold, is dropped as usual, and the newest is written; the hold's end deletes the first's seg/ copy.
//	          The twin, Fs66NoHold, writes only the newest
//	FS-6      Fs6NowShredUnderAHold, a clause of FS-6's registered case: a --now delete under the hold. The shred's
//	          first pass destroys the keys (the slots and the group's objects) and stops at step 4, the ciphertext
//	          kept; a day on, evacuation packs the repo's records, which nothing deletes while the hold stands; api's
//	          pass ends the hold, and the next passes delete everything and write the tombstone. The twin,
//	          Fs6NowShredNoHold, shreds to the tombstone at once
//
// FS-69's purges are the evacuation's sweep: no evs host constructs EVSB-M10-01's Purger yet, so its certainty-time
// DELETEs, and a hold placed between them, wait for that wiring.

package fault

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/gkmservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var (
	Fs69Case     = Register("FS-69", "", []Tier{TierT2, TierT3}, Fs69HoldBeforeAReplacement)
	Fs66HoldCase = Register("FS-66", "hold", []Tier{TierT2, TierT3}, Fs66HoldKeepsStagedFromBeforeIt)
)

// The checks the purge's hold cases name after every step: the world's, format 2's, FI-5, FI-16 and FI-17.
func holdCaseChecks(world *EvsWorld) []Invariant {
	return world.Checks(world.FormatHolds(), FI(5), FI(16), FI(17))
}

// A step action: path's ordinal-th committed version's segments, from 1, are stored or not.
func holdCaseVersionStored(world *EvsWorld, path string, ordinal int, stored bool) func(ctx context.Context, net *Net) error {
	return world.ExpectSegments(fmt.Sprintf("%s's version %d", path, ordinal), stored, func() ([][]byte, error) {
		entries, err := world.CommittedEntries(path)
		if err != nil {
			return nil, err
		}
		if len(entries) < ordinal {
			return nil, fmt.Errorf("%s has %d committed versions, not %d", path, len(entries), ordinal)
		}
		return entries[ordinal-1].SegmentIds(), nil
	})
}

// ----- FS-69 -----

// See the file header.
func Fs69HoldBeforeAReplacement(net *Net) *Schedule {
	schedule := fs69Schedule(net, true)
	schedule.Twin = Fs69NoHold
	return schedule
}

// See the file header.
func Fs69NoHold(net *Net) *Schedule {
	return fs69Schedule(net, false)
}

func fs69Schedule(net *Net, held bool) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	holds := NewEvsWorldHolds(world, nil)
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.WriteVersioning("admin", "p.bin", fs72Kind5Content("fs69 p 1"), sidecar.EvsVersioningOff)},
	}
	if held {
		steps = append(steps, &Step{Actor: "abuse", Action: holds.Place("order", fs92Order)})
	}
	steps = append(steps, []*Step{
		{Advance: holds.settings.BindTimeout},
		{Actor: "admin", Action: world.WriteVersioning("admin", "p.bin", fs72Kind5Content("fs69 p 2"), "")},
		{Actor: "admin", Action: world.WriteVersioning("admin", "p.bin", fs72Kind5Content("fs69 p 3"), "")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "p.bin", 1)},
		{Advance: 30 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, holdCaseNoAlarms)},
	}...)
	if !fsDropSettled(net) {
		// the sweep's deletes wait on settle, as fs68.go reads such a Net
		steps = append(steps, &Step{Actor: "check", Action: holdCaseVersionStored(world, "p.bin", 2, true)})
		return &Schedule{Id: "FS-69", Steps: steps, Check: holdCaseChecks(world), Tiers: []Tier{TierT2, TierT3}}
	}
	steps = append(steps, []*Step{
		// what existed at the placement is kept; what was written and replaced under the hold is purged as usual
		{Actor: "check", Action: holdCaseVersionStored(world, "p.bin", 1, held)},
		{Actor: "check", Action: holdCaseVersionStored(world, "p.bin", 2, false)},
		{Actor: "check", Action: holdCaseVersionStored(world, "p.bin", 3, true)},
		{Actor: "reader", Action: world.Verify("reader", "p.bin")},
	}...)
	if held {
		steps = append(steps, []*Step{
			{Actor: "abuse", Action: holds.ToExpiry("order")},
			{Actor: "abuse", Action: holds.Pass("order")},
			{Actor: "check", Action: holds.Swept()},
			// the hold's end purges each candidate it kept
			{Actor: "check", Action: holdCaseVersionStored(world, "p.bin", 1, false)},
			{Actor: "check", Action: holdCaseVersionStored(world, "p.bin", 3, true)},
			{Actor: "reader", Action: world.Verify("reader", "p.bin")},
		}...)
	}
	return &Schedule{Id: "FS-69", Steps: steps, Check: holdCaseChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// An EvacuateAt check: the run raised no alarm.
func holdCaseNoAlarms(result *evsservice.EvacuationResult, alarms []string) error {
	if len(alarms) != 0 {
		return fmt.Errorf("it alarmed: %v", alarms)
	}
	return nil
}

// See the file header.
func Fs69HoldBetweenSweepDeletes(net *Net) *Schedule {
	schedule := fs69BetweenSchedule(net, true)
	schedule.Twin = Fs69NoHoldBetweenSweepDeletes
	return schedule
}

// Fs69HoldBetweenSweepDeletes with no hold placed: the sweep purges both.
func Fs69NoHoldBetweenSweepDeletes(net *Net) *Schedule {
	return fs69BetweenSchedule(net, false)
}

func fs69BetweenSchedule(net *Net, held bool) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	holds := NewEvsWorldHolds(world, nil)
	steps := []*Step{{Actor: "admin", Action: world.Setup}}
	for _, path := range []string{"p.bin", "q.bin"} {
		steps = append(steps, []*Step{
			{Actor: "admin", Action: world.WriteVersioning("admin", path, fs72Kind5Content("fs69 "+path+" 1"), sidecar.EvsVersioningOff)},
			{Actor: "admin", Action: world.WriteVersioning("admin", path, fs72Kind5Content("fs69 "+path+" 2"), "")},
		}...)
	}
	steps = append(steps, []*Step{
		{Advance: 30 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, holdCaseNoAlarms), Background: true},
	}...)
	if !fsDropSettled(net) {
		steps = append(steps, &Step{Actor: "taskworker", Join: true})
		return &Schedule{Id: "FS-69 between sweep deletes", Steps: steps, Check: holdCaseChecks(world), Tiers: []Tier{TierT2, TierT3}}
	}
	release := []*Step{{Actor: "taskworker", Await: evsservice.BarrierSweepDeleteAfter}}
	if held {
		release = append(release, &Step{Actor: "abuse", Action: holds.Place("order", fs92Order)}, &Step{Advance: holds.settings.BindTimeout})
	}
	release = append(release, &Step{Release: []string{sidecartest.ActorBarrierSite("taskworker", evsservice.BarrierSweepDeleteAfter)}})
	steps = append(steps, release...)
	steps = append(steps, []*Step{
		{Actor: "taskworker", Join: true},
		{Actor: "check", Action: holdCaseReplacedStored(world, map[bool]int{true: 1, false: 0}[held])},
		{Actor: "reader", Action: world.Verify("reader", "p.bin", "q.bin")},
	}...)
	return &Schedule{Id: "FS-69 between sweep deletes", Steps: steps, Check: holdCaseChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: of p.bin's and q.bin's replaced versions, exactly storedCount keep their segments.
func holdCaseReplacedStored(world *EvsWorld, storedCount int) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		cluster, err := net.Host().Blobs.SegmentCluster()
		if err != nil {
			return err
		}
		stored := 0
		for _, path := range []string{"p.bin", "q.bin"} {
			entries, err := world.CommittedEntries(path)
			if err != nil {
				return err
			}
			if len(entries) != 2 {
				return fmt.Errorf("%s has %d committed versions, not 2", path, len(entries))
			}
			for _, id := range entries[0].SegmentIds() {
				_, err := cluster.Head(sidecartest.InspectContext(ctx), evsservice.SegmentKey(world.RepoId, [32]byte(id)))
				switch {
				case err == nil:
					stored += 1
				case !errors.Is(err, sidecar.ErrBlobNotFound):
					return err
				}
			}
		}
		if stored != storedCount {
			return fmt.Errorf("%d replaced versions keep their segments, not %d", stored, storedCount)
		}
		return nil
	}
}

// See the file header.
func Fs69EraseUnderTheHold(net *Net) *Schedule {
	schedule := fs69EraseSchedule(net, true)
	schedule.Twin = Fs69EraseWithNoHold
	return schedule
}

// Fs69EraseUnderTheHold with no hold placed.
func Fs69EraseWithNoHold(net *Net) *Schedule {
	return fs69EraseSchedule(net, false)
}

func fs69EraseSchedule(net *Net, held bool) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_RECORD, false))
	holds := NewEvsWorldHolds(world, nil)
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.WriteVersioning("admin", "v.bin", fs72Kind5Content("fs69 v 1"), sidecar.EvsVersioningOff)},
		{Actor: "admin", Action: world.WriteVersioning("admin", "v.bin", fs72Kind5Content("fs69 v 2"), "")},
	}
	if held {
		steps = append(steps, &Step{Actor: "abuse", Action: holds.Place("order", fs92Order)})
	}
	steps = append(steps, []*Step{
		{Advance: holds.settings.BindTimeout},
		// keys gone when the ERASE answers, the ciphertext where it was, under the hold as without it
		{Actor: "admin", Action: world.EraseAtOnce("admin", "v.bin")},
		{Actor: "reader", Action: world.ReadVersionEnds("reader", "v.bin", 2, EvsWorldReadsErased())},
	}...)
	return &Schedule{Id: "FS-69 erase", Steps: steps, Check: holdCaseChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// ----- FS-66 -----

// See the file header.
func Fs66HoldKeepsStagedFromBeforeIt(net *Net) *Schedule {
	schedule := fs66HoldSchedule(net, true)
	schedule.Twin = Fs66NoHold
	return schedule
}

// See the file header.
func Fs66NoHold(net *Net) *Schedule {
	return fs66HoldSchedule(net, false)
}

func fs66HoldSchedule(net *Net, held bool) *Schedule {
	world := NewEvsWorld(net, fsDropWorldSettings(protocol.RepoKind_REPO_KIND_GENERAL, false))
	holds := NewEvsWorldHolds(world, nil)
	steps := []*Step{
		{Actor: "admin", Action: world.Setup},
		{Actor: "admin", Action: world.WriteVersioning("admin", "h.txt", fs72StagedContent("fs66 h 1"), sidecar.EvsVersioningOff)},
		{Advance: time.Minute},
	}
	if held {
		steps = append(steps, &Step{Actor: "abuse", Action: holds.Place("order", fs92Order)})
	}
	steps = append(steps, []*Step{
		// past the bind, and into a batch minute that began after the placement: evacuation keeps a staged record
		// whose batch's minute began before it, every doubt keeping data
		{Advance: time.Minute},
		{Actor: "admin", Action: world.WriteVersioning("admin", "h.txt", fs72StagedContent("fs66 h 2"), "")},
		{Advance: 10 * time.Minute},
		{Actor: "admin", Action: world.WriteVersioning("admin", "h.txt", fs72StagedContent("fs66 h 3"), "")},
		{Actor: "admin", Action: world.ExpectVersioning("admin", "h.txt", 1)},
		{Advance: 30 * time.Hour},
		{Actor: "taskworker", Action: world.EvacuateAt(sidecar.EvsRepoFormat2, holdCaseNoAlarms)},
	}...)
	if !fsDropSettled(net) {
		return &Schedule{Id: "FS-66 hold", Steps: steps, Check: holdCaseChecks(world), Tiers: []Tier{TierT2, TierT3}}
	}
	steps = append(steps, []*Step{
		// a staged record from a batch before the placement is written to seg/; one written and replaced under the
		// hold is dropped with its batch; the newest is written
		{Actor: "check", Action: holdCaseVersionStored(world, "h.txt", 1, held)},
		{Actor: "check", Action: holdCaseVersionStored(world, "h.txt", 2, false)},
		{Actor: "check", Action: holdCaseVersionStored(world, "h.txt", 3, true)},
		{Actor: "reader", Action: world.Verify("reader", "h.txt")},
	}...)
	if held {
		steps = append(steps, []*Step{
			{Actor: "abuse", Action: holds.ToExpiry("order")},
			{Actor: "abuse", Action: holds.Pass("order")},
			{Actor: "check", Action: holds.Swept()},
			{Actor: "check", Action: holdCaseVersionStored(world, "h.txt", 1, false)},
			{Actor: "check", Action: holdCaseVersionStored(world, "h.txt", 3, true)},
			{Actor: "reader", Action: world.Verify("reader", "h.txt")},
		}...)
	}
	return &Schedule{Id: "FS-66 hold", Steps: steps, Check: holdCaseChecks(world), Tiers: []Tier{TierT2, TierT3}}
}

// ----- FS-6 -----

// See the file header.
func Fs6NowShredUnderAHold(net *Net) *Schedule {
	schedule := fs6HoldSchedule(net, true)
	schedule.Twin = Fs6NowShredNoHold
	return schedule
}

// See the file header.
func Fs6NowShredNoHold(net *Net) *Schedule {
	return fs6HoldSchedule(net, false)
}

func fs6HoldSchedule(net *Net, held bool) *Schedule {
	world := NewEvsWorld(net, nil)
	holds := NewEvsWorldHolds(world, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs6 hold a", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "d/b.txt", EvsWorldContent("fs6 hold b", 40*1024))},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "d/b.txt")},
	}
	if held {
		steps = append(steps, &Step{Actor: "abuse", Action: holds.Place("order", fs92Order)})
	}
	steps = append(steps, []*Step{
		{Advance: holds.settings.BindTimeout},
		{Actor: "writerA", Action: world.DeleteRepo("writerA", true)},
		{Actor: "check", Action: world.ExpectRepoState(protocol.EvsRepoState_EVS_REPO_SHREDDING)},
		{Advance: 20 * time.Second},
	}...)
	if !held {
		steps = append(steps, fs6ShredToTheEnd(world)[3:]...)
		return &Schedule{Id: "FS-6 a --now shred under a hold", Steps: steps, Check: world.Checks(FI(5)), Tiers: []Tier{TierT2, TierT3}}
	}
	steps = append(steps, []*Step{
		// keys gone, ciphertext kept: the first pass stops at step 4
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredHeld)},
		{Actor: "check", Action: holdCaseKeysGoneCiphertextKept(world)},
		// a day on, evacuation packs the repo's batched records, which nothing deletes while the hold stands
		{Advance: 26 * time.Hour},
		{Actor: "taskworker", Action: world.Evacuate()},
		{Actor: "check", Action: holdCaseRecordsPacked(world)},
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredHeld)},
		{Actor: "check", Action: holdCaseRecordsPacked(world)},
		// api's expiry ends the hold, and the shred goes on to the tombstone
		{Actor: "abuse", Action: holds.ToExpiry("order")},
		{Actor: "abuse", Action: holds.Pass("order")},
		{Actor: "shred", Action: world.Shred(false)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredFirstPassDone)},
		{Advance: 10 * time.Minute},
		{Actor: "shred", Action: world.Shred(true)},
		{Actor: "check", Action: world.ExpectShred(evsservice.EvsShredShredded)},
		{Actor: "check", Action: world.ExpectShredded()},
	}...)
	return &Schedule{Id: "FS-6 a --now shred under a hold", Steps: steps, Check: world.Checks(FI(5)), Tiers: []Tier{TierT2, TierT3}}
}

// A step action: the repo's keys are gone, its slots and its group's objects deleted, and its ciphertext is stored.
func holdCaseKeysGoneCiphertextKept(world *EvsWorld) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		inspect := sidecartest.InspectContext(ctx)
		first, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		slotPrefix := evsservice.SlotKey(world.RepoId, sidecar.Id{})
		slotPrefix = slotPrefix[:strings.LastIndex(slotPrefix, "/")+1]
		if slots, _, err := first.List(inspect, slotPrefix, "", 1); err != nil || len(slots) != 0 {
			return fmt.Errorf("the repo's slots under the hold: %d, %v", len(slots), err)
		}
		world.stateLock.Lock()
		gkm := world.gkm
		world.stateLock.Unlock()
		if groupId, _, ok := gkm.Newest(world.RepoId); ok {
			if objects, _, err := first.List(inspect, gkmservice.GkmGroupPrefix(groupId), "", 1); err != nil || len(objects) != 0 {
				return fmt.Errorf("the repo's group objects under the hold: %d, %v", len(objects), err)
			}
		}
		segments, err := world.segmentKeys(ctx, net)
		if err != nil {
			return err
		}
		if len(segments) == 0 {
			return errors.New("the hold kept no ciphertext: the repo's segments are gone")
		}
		return nil
	}
}

// A step action: the repo's records are in packs or parcels, its segments stored.
func holdCaseRecordsPacked(world *EvsWorld) func(ctx context.Context, net *Net) error {
	return func(ctx context.Context, net *Net) error {
		inspect := sidecartest.InspectContext(ctx)
		segment, err := net.Host().Blobs.SegmentCluster()
		if err != nil {
			return err
		}
		first, err := net.Host().Blobs.FirstCluster()
		if err != nil {
			return err
		}
		packPrefix := evsservice.PackKey(world.RepoId, sidecar.Id{})
		packPrefix = packPrefix[:strings.LastIndex(packPrefix, "/")+1]
		parcelPrefix := evsservice.ParcelKey(world.RepoId, sidecar.Id{})
		parcelPrefix = parcelPrefix[:strings.LastIndex(parcelPrefix, "/")+1]
		packs, _, err := segment.List(inspect, packPrefix, "", 1)
		if err != nil {
			return err
		}
		parcels, _, err := first.List(inspect, parcelPrefix, "", 1)
		if err != nil {
			return err
		}
		if len(packs) == 0 && len(parcels) == 0 {
			return errors.New("the repo's records are in no pack or parcel under the hold")
		}
		segments, err := world.segmentKeys(ctx, net)
		if err != nil {
			return err
		}
		if len(segments) == 0 {
			return errors.New("the repo's segments went under the hold")
		}
		return nil
	}
}
