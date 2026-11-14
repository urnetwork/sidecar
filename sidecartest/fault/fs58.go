// FS-58 (§22.8; §11.7's folds, versions and newest rule, I-EVS-8, D-EVS-31; EVS1-M2-41) on the evs world
// (evs_world.go).
//
// The registered case, Fs58FoldBetweenReadAndRerun, beside its twin: x.txt exists at v1; writerA's push A, based on
// it, reads head v1 and x.txt's entry and is held before step 7; writerB changes x.txt at v2, a fold on writerB's
// instance takes v2 into x.txt's entry, and writerB's change of y.txt raises folded_through past it; released, A's
// CAS fails, and its rerun, keeping the folded_through its entries were read after, refuses it 409 naming x.txt. The
// reader reads x.txt through the cluster's head and evs's head cache at each step and sees B's version and nothing
// above the head it is served. Its twin, Fs58DisjointRerun, has A change z.txt instead, and A's rerun commits.
//
// The clause beside it, Fs58FoldKilledAndRaced: x.txt changed in four unfolded versions, read through the cluster's
// head and the cache; a fold killed after its first entry write, then run again; two folds of the same versions on
// two instances racing, one held before its entry write while the other finishes; reads at each step.
//
// FS-58's page-out of a directory changed in every version, folds held until 255 versions (429 FOLD_BEHIND), the
// idle ref's PATH_EPOCH folding every version, the newer-head and listing cases, the removal folds of D and D/x with
// late marker PUTs, a file removed and re-created across a marker's collection and a path-epoch copy, versions not
// max(b, m) + 1 refused, and the collection window with its clocks 50 ms off are EVS1-M2-41's report's; FI-15 holds
// through the world's checks (TEST-M2-04).

package fault

import (
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs58 = Register("FS-58", "", []Tier{TierT2, TierT3}, Twin(Fs58FoldBetweenReadAndRerun, Fs58DisjointRerun))

// See the file header.
func Fs58FoldBetweenReadAndRerun(net *Net) *Schedule {
	schedule := fs58Schedule(net, "x.txt")
	schedule.Refuses = "writerA's change of x.txt based on v1, 409 naming it after a fold and a horizon-raising commit"
	return schedule
}

// See the file header.
func Fs58DisjointRerun(net *Net) *Schedule {
	return fs58Schedule(net, "z.txt")
}

func fs58Schedule(net *Net, pathA string) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs58 x 1", 200))},
		{Actor: "writerA", Action: world.Write("writerA", "z.txt", EvsWorldContent("fs58 z 1", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "y.txt", EvsWorldContent("fs58 y 1", 200))},
		{Actor: "writerA", Action: world.WriteAny("writerA", pathA, EvsWorldContent("fs58 by A", 200)), Background: true},
		// x.txt's and z.txt's creations pass
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: 2},
		{Actor: "writerB", Action: world.Write("writerB", "x.txt", EvsWorldContent("fs58 x by B", 200))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "reader", Action: world.VerifyCached("reader", "x.txt")},
		{Actor: "folder", Action: world.Fold("evs3")},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
		{Actor: "writerB", Action: world.Write("writerB", "y.txt", EvsWorldContent("fs58 y 2", 200))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Actor: "reader", Action: world.VerifyCached("reader", "x.txt", "y.txt")},
		{Release: []string{evsservice.BarrierHeadCasBefore}},
		{Actor: "writerA", Join: true},
	}
	if pathA == "x.txt" {
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectRefused("writerA", "x.txt", protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)})
	} else {
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectCommitted("writerA", "z.txt")})
	}
	steps = append(steps, []*Step{
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt", "z.txt")},
		{Actor: "reader", Action: world.VerifyCached("reader", "x.txt", "y.txt", "z.txt")},
	}...)
	return &Schedule{Id: "FS-58", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header.
func Fs58FoldKilledAndRaced(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{{Actor: "writerA", Action: world.Setup}}
	for version := 1; version <= 4; version += 1 {
		steps = append(steps, &Step{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs58 x "+string(rune('0'+version)), 200))})
	}
	steps = append(steps, []*Step{
		{Actor: "writerB", Action: world.Write("writerB", "docs/a.txt", EvsWorldContent("fs58 docs/a", 200))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "docs/a.txt")},
		{Actor: "reader", Action: world.VerifyCached("reader", "x.txt", "docs/a.txt")},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "a.txt")},
		// a fold killed after its first entry write
		{Actor: "folderA", Action: world.Fold("evsr"), Background: true},
		{Actor: "folderA", Await: evsservice.BarrierFoldEntryWriteAfter},
		{Actor: "folderA", Kill: true},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "docs/a.txt")},
		{Actor: "folderB", Action: world.Fold("evsr")},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "docs/a.txt")},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "a.txt")},
		// two folds of the same new versions race, one held before its first entry write
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs58 x 5", 200))},
		{Actor: "writerB", Action: world.Write("writerB", "docs/b.txt", EvsWorldContent("fs58 docs/b", 200))},
		{Actor: "folderC", Action: world.Fold("evs2"), Background: true},
		{Actor: "folderC", Await: evsservice.BarrierFoldEntryWriteBefore},
		{Actor: "folderD", Action: world.Fold("evs3")},
		{Release: []string{evsservice.BarrierFoldEntryWriteBefore}},
		{Actor: "folderC", Join: true},
		{Advance: time.Second},
		{Actor: "writerB", Action: world.Write("writerB", "docs/c.txt", EvsWorldContent("fs58 docs/c", 200))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "docs/a.txt", "docs/b.txt", "docs/c.txt")},
		{Actor: "reader", Action: world.VerifyCached("reader", "x.txt", "docs/b.txt")},
		{Actor: "reader", Action: world.VerifyListing("reader", "docs", "a.txt", "b.txt", "c.txt")},
	}...)
	return &Schedule{Id: "FS-58 folds killed and raced", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
