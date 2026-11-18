// FS-4 (§22.8; §11.6's path epochs, DESIGN-DETAILS 9.2.5 to 9.2.7 and 9.6; EVS1-M2-41) on the evs world
// (evs_world.go): the client's floors, retoken and mapper (EVS1-M2-28, EVS1-M2-47) against evs's 5e, fences and copy
// job (EVS1-M2-44), end to end.
//
// The registered case, Fs4CutOverUnderARemoval: files written in epoch 1; a reader leaves the repo, so the next
// generation is a REMOVE, whose due is batched as every due is (QD-1046): a creation then lands at once in epoch 1 and
// records the due on the head, blocking nothing, and a modification commits beside it; writerA's mapper, the device
// that rotated, builds, uploads and commits the PATH_EPOCH, held at its head CAS while the reader reads every file and
// lists every directory in epoch 1; the head then stands at epoch 2 over source 1, and the reader reads and lists the
// same across the cut-over, the creation among them, before evs's copy job and after it drops the source; and a
// creation lands in epoch 2 and lists. Before QD-1046 the case held the creation while an immediate removal was due,
// a refusal beside a twin that had nobody leave; with no refusal left in it, it names no twin.
//
// The clause Fs4TwoSources (fs4_sources.go) cuts over twice with no copy running, so reads and listings find every
// file across sources 2 and 1 and then across the copy that drops them.
//
// FS-4's further clauses (inserts, removals and renames after a map's enumeration reaching its tail, steady creation
// under a batched epoch with the 2-min block, the overdue alarm, old-epoch parts and seals 412 PATH_EPOCH, a mapper
// killed after half its parts, the carried directory D through p1, p2 and p3, removals after cut-over before the copy,
// a move between one round's GETs, no late token, EPOCH_SOURCES_FULL after the fence, kills at each copy boundary and
// a lease holder re-subscribing) are EVS1-M2-41's report's; FI-3 holds through the world's checks (TEST-M2-05).

package fault

import (
	"github.com/urnetwork/sidecar"
	"github.com/urnetwork/sidecar/evsservice"
)

var Fs4 = Register("FS-4", "", []Tier{TierT2, TierT3}, Fs4CutOverUnderARemoval)

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
func Fs4CutOverUnderARemoval(net *Net) *Schedule {
	world := NewEvsWorld(net, fs4WorldSettings())
	steps := []*Step{{Actor: "writerA", Action: world.Setup}}
	for _, path := range fs4Files {
		steps = append(steps, &Step{Actor: "writerA", Action: world.Write("writerA", path, EvsWorldContent("fs4 "+path, 200))})
	}
	files := append([]string{"docs/new.md"}, fs4Files...)
	steps = append(steps, []*Step{
		{Actor: "admin", Action: world.DropReader("leaver")},
		// the crossing: a creation, which no due holds
		{Actor: "writerA", Action: world.Write("writerA", "docs/new.md", EvsWorldContent("fs4 docs/new.md", 200))},
		{Actor: "check", Action: world.ExpectBatchedDue()},
		{Actor: "writerA", Action: world.Write("writerA", "docs/old.md", EvsWorldContent("fs4 docs/old.md 2", 200))},
		{Actor: "writerA", Action: world.TickMapper("writerA"), Background: true},
		// every file's CAS on evs1 passed, the creation's and the modification's too
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: len(fs4Files) + 2},
		{Actor: "reader", Action: world.Verify("reader", files...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "new.md", "old.md")},
		{Actor: "reader", Action: world.VerifyListing("reader", "bulk", "f00", "f01", "f02")},
		{Release: []string{evsservice.BarrierHeadCasBefore}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectEpoch(2, 1)},
		{Actor: "reader", Action: world.Verify("reader", files...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "new.md", "old.md")},
		{Actor: "reader", Action: world.VerifyListing("reader", "bulk", "f00", "f01", "f02")},
		{Actor: "copier", Action: world.CopyInto(2)},
		{Actor: "check", Action: world.ExpectEpoch(2)},
		{Actor: "reader", Action: world.Verify("reader", files...)},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "new.md", "old.md")},
		{Actor: "writerA", Action: world.Write("writerA", "docs/newer.md", EvsWorldContent("fs4 docs/newer.md", 200))},
		{Actor: "reader", Action: world.Verify("reader", "docs/newer.md", "docs/new.md", "docs/old.md")},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "new.md", "newer.md", "old.md")},
	}...)
	return &Schedule{Id: "FS-4", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
