// FS-4 (§22.8; §11.6's path epochs, DESIGN-DETAILS 9.2.5 to 9.2.7 and 9.6; EVS1-M2-41) on the evs world
// (evs_world.go): the client's floors, retoken and mapper (EVS1-M2-28, EVS1-M2-47) against evs's 5e, fences and copy
// job (EVS1-M2-44), end to end.
//
// The registered case, Fs4CutOverUnderAnImmediateRemoval, beside its twin: files written in epoch 1; a reader leaves
// the repo, so the next generation is a REMOVE whose crossing blocks creation; a creation then waits, sending nothing,
// with ErrEvsPathEpochDue, while a modification commits and records the due on the head; writerA's mapper builds,
// uploads and commits the PATH_EPOCH, held at its head CAS while the reader reads every file and lists every
// directory in epoch 1; the head then stands at epoch 2 over source 1, and the reader reads and lists the same across
// the cut-over, before evs's copy job and after it drops the source; and the creation lands in epoch 2 and lists. The
// twin, Fs4NoRemoval, has nobody leave: the creation lands at once in epoch 1 and no PATH_EPOCH is made.
//
// FS-4's further clauses (inserts, removals and renames after a map's enumeration reaching its tail, a tail omitting a
// creation refused 409, steady creation under an immediate and a batched epoch with the 2-min block, the overdue
// alarm, old-epoch parts and seals 412 PATH_EPOCH, a mapper killed after half its parts, the paused copy with two
// removals and three sources, the carried directory D through p1, p2 and p3, removals after cut-over before the copy,
// a move between one round's GETs, no late token, EPOCH_SOURCES_FULL after the fence, kills at each copy boundary and
// a lease holder re-subscribing) are EVS1-M2-41's report's; FI-3's oracle is not bound (TEST-M2-05).

package fault

import (
	"context"
	"fmt"

	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

var Fs4 = Register("FS-4", "", []Tier{TierT2, TierT3}, Twin(Fs4CutOverUnderAnImmediateRemoval, Fs4NoRemoval))

// The default world, a reader that leaves the repo, and one map part uploaded at a time.
func fs4WorldSettings() *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{Name: "leaver", Instances: []string{"evsr"}})
	settings.AdjustClient = func(device string, settings *sidecar.EvsSettings) {
		settings.MapUploadCount = 1
	}
	return settings
}

// The files every FS-4 schedule writes in epoch 1.
var fs4Files = []string{"docs/old.md", "bulk/f00", "bulk/f01", "bulk/f02"}

// See the file header.
func Fs4CutOverUnderAnImmediateRemoval(net *Net) *Schedule {
	world := NewEvsWorld(net, fs4WorldSettings())
	steps := []*Step{{Actor: "writerA", Action: world.Setup}}
	for _, path := range fs4Files {
		steps = append(steps, &Step{Actor: "writerA", Action: world.Write("writerA", path, EvsWorldContent("fs4 "+path, 200))})
	}
	steps = append(steps, []*Step{
		{Actor: "admin", Action: world.DropReader("leaver")},
		{Actor: "writerA", Action: world.WriteDue("writerA", "docs/new.md")},
		{Actor: "writerA", Action: world.Write("writerA", "docs/old.md", EvsWorldContent("fs4 docs/old.md 2", 200))},
		{Actor: "check", Action: world.Expect("the head records the blocking due", func(ctx context.Context) error {
			head, err := world.Head(ctx)
			if err != nil {
				return err
			}
			if epoch := head.GetPathEpoch(); epoch.GetDueGeneration() < 2 || !epoch.GetDueBlocksCreation() {
				return fmt.Errorf("the head's path epoch %v", epoch)
			}
			return nil
		})},
		{Actor: "writerA", Action: world.TickMapper("writerA"), Background: true},
		// every file's CAS on evs1 passed, the modification's too
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: len(fs4Files) + 1},
		{Actor: "reader", Action: world.Verify("reader", fs4Files...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "bulk", "f00", "f01", "f02")},
		{Release: []string{evsservice.BarrierHeadCasBefore}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectEpoch(2, 1)},
		{Actor: "reader", Action: world.Verify("reader", fs4Files...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "old.md")},
		{Actor: "reader", Action: world.VerifyListing("reader", "bulk", "f00", "f01", "f02")},
		{Actor: "copier", Action: world.CopyInto(2)},
		{Actor: "check", Action: world.ExpectEpoch(2)},
		{Actor: "reader", Action: world.Verify("reader", fs4Files...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "old.md")},
		{Actor: "writerA", Action: world.Write("writerA", "docs/new.md", EvsWorldContent("fs4 docs/new.md", 200))},
		{Actor: "reader", Action: world.Verify("reader", "docs/new.md", "docs/old.md")},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "new.md", "old.md")},
	}...)
	return &Schedule{
		Id: "FS-4", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3},
		Refuses: "a creation while an immediate removal is due, held with ErrEvsPathEpochDue until the map lands",
	}
}

// See the file header.
func Fs4NoRemoval(net *Net) *Schedule {
	world := NewEvsWorld(net, fs4WorldSettings())
	steps := []*Step{{Actor: "writerA", Action: world.Setup}}
	for _, path := range fs4Files {
		steps = append(steps, &Step{Actor: "writerA", Action: world.Write("writerA", path, EvsWorldContent("fs4 "+path, 200))})
	}
	steps = append(steps, []*Step{
		{Actor: "writerA", Action: world.Write("writerA", "docs/new.md", EvsWorldContent("fs4 docs/new.md", 200))},
		{Actor: "writerA", Action: world.TickMapper("writerA")},
		{Actor: "check", Action: world.ExpectEpoch(1)},
		{Actor: "reader", Action: world.Verify("reader", append([]string{"docs/new.md"}, fs4Files...)...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "new.md", "old.md")},
	}...)
	return &Schedule{Id: "FS-4", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
