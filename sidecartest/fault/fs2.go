// FS-2 (§22.8; §11.8's 5g and outcome rows, I-EVS-2; EVS1-M2-40) on the evs world (evs_world.go): writerA and writerB
// each push one path based on its committed version v, each held at its instance's head CAS once its batch record is
// written; A's CAS wins at v+1; B's fails its precondition, its rerun on the new head refuses it 409 PATH_CONFLICT
// naming the path, and its record stays in its batch until the clock passes 26 h and evacuation's Resolve finds it
// dead, then goes, while A's is kept. The reader reads the path at each hold. Its twin, Fs2Disjoint, is the same with
// B writing another path: B's rerun commits at v+2 and evacuation keeps both records.
//
// FS-2's new slots are a slot-keyed repo's, which the world's general repo writes none of: EVS1-M2-40's report keeps
// them. FI-3 holds through the world's checks (TEST-M2-05).

package fault

import (
	"context"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs2 = Register("FS-2", "", []Tier{TierT2, TierT3}, Twin(Fs2SamePath, Fs2Disjoint))

// See the file header.
func Fs2SamePath(net *Net) *Schedule {
	schedule := fs2Schedule(net, "x.txt")
	schedule.Refuses = "writerB's push of x.txt based on its committed version, 409 PATH_CONFLICT after writerA's commit"
	return schedule
}

// See the file header.
func Fs2Disjoint(net *Net) *Schedule {
	return fs2Schedule(net, "y.txt")
}

// The two pushes, writerB's of pathB.
func fs2Schedule(net *Net, pathB string) *Schedule {
	world := NewEvsWorld(net, nil)
	refused := pathB == "x.txt"
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs2 x v", 300))},
		{Actor: "writerB", Action: world.Write("writerB", "y.txt", EvsWorldContent("fs2 y v", 300))},
		// both plan on the head holding x and y at v, and wait at their CAS with their records written
		{Actor: "writerA", Action: world.WriteAny("writerA", "x.txt", EvsWorldContent("fs2 x by A", 300)), Background: true},
		// x's first CAS passes
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: 1},
		{Actor: "writerB", Action: world.WriteAny("writerB", pathB, EvsWorldContent("fs2 by B", 300)), Background: true},
		// y's first CAS passes
		{Actor: "evs3", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: 1},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Release: []string{sidecartest.ActorBarrierSite("evs1", evsservice.BarrierHeadCasBefore)}},
		{Actor: "writerA", Join: true},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Release: []string{sidecartest.ActorBarrierSite("evs3", evsservice.BarrierHeadCasBefore)}},
		{Actor: "writerB", Join: true},
		{Actor: "check", Action: world.ExpectCommitted("writerA", "x.txt")},
	}
	if refused {
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectRefused("writerB", "x.txt", protocol.EvsRefusalCode_EVS_REFUSAL_PATH_CONFLICT)})
	} else {
		steps = append(steps, &Step{Actor: "check", Action: world.ExpectCommitted("writerB", "y.txt")})
	}
	// B's record stays in its batch until evacuation finds it dead
	steps = append(steps, []*Step{
		{Actor: "check", Action: world.Expect("writerB's newest push keeps its record before evacuation", func(ctx context.Context) error {
			return fs2RecordCount(ctx, world, 1)
		})},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.Evacuate()},
		{Actor: "check", Action: world.Expect("evacuation took writerB's newest record out of its batch", func(ctx context.Context) error {
			return fs2RecordCount(ctx, world, 0)
		})},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
	}...)
	return &Schedule{Id: "FS-2", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// writerB's newest push holds count records in pb/ batches.
func fs2RecordCount(ctx context.Context, world *EvsWorld, count int) error {
	pushIds := world.DevicePushIds("writerB")
	if len(pushIds) == 0 {
		return fmt.Errorf("writerB posted no push")
	}
	held, err := world.BatchRecordCount(sidecartest.InspectContext(ctx), pushIds[len(pushIds)-1])
	if err != nil {
		return err
	}
	if held != count {
		return fmt.Errorf("its batches hold %d of its records, not %d", held, count)
	}
	return nil
}
