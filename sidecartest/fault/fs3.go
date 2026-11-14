// FS-3 (§22.8; §11.8's 5d gate and 412 rows, §10.6, I-EVS-3; EVS1-M2-40) on the evs world (evs_world.go). FS-3 is on
// §22.8's unknown list, so every write each clause issues also runs with its response lost.
//
// The registered case, Fs3GateClosed, beside its twin: x.txt and y.txt exist; writerA's push A changing x.txt is held
// at evs1's head CAS once its checks pass; a reader leaves the repo, a projection drop that closes the gate on
// generation 1; writerB, changing y.txt, rotates to generation 2 and commits disjointly, the crossing recording the
// path epoch's due; A, released, fails its CAS, and its rerun of 5 (b-h) on the new head refuses it 412 GATE_CLOSED,
// the head's pins being newer; writerA builds the write again under a new push id and generation 2, and it commits.
// The twin, Fs3GateOpen, is the same with nobody leaving: B commits under generation 1 and A's rerun commits by the
// disjoint-retry path. Only changes are made, since a creation waits out the due a removal leaves (FS-4's).
//
// The clause beside it, Fs3StepSevenPastFiveSeconds: A held after its step 6, before step 7's window, while the
// reader leaves and 25 s pass, inside the lb's read timeout, with no other commit: its step 7 is past 5 s of its step
// 4, so it reruns the checks, which must refuse it GATE_CLOSED against the newest state evs holds (§11.8's timing row),
// and writerA's next push id commits under generation 2. Its twin, Fs3StepSevenGateOpen, is the same with nobody
// leaving: A's rerun past the window commits under generation 1. An attempt reads its gate view again at each run of
// step 4 (QD-660, answering evs1-m2-40-gate-view-rerun): with the view bound once at arrival, as the engine first had
// it, the rerun judged 5d against a state from before the reader left and committed under generation 1.
// TestFs3StepSevenPastFiveSeconds runs the clause under FS-3's rules.
//
// FS-3 also names A's PUT timing out after the gate closes, its fence and the 200 when its first PUT applied before
// the fence, and the multipart seal, deposit, new ref, repo delete, grant expiry and evs restart before the CAS:
// EVS1-M2-40's report keeps them. Nothing committing under the old generation past §10.6's window is FI-3's clause,
// which the world's checks name (TEST-M2-05).

package fault

import (
	"context"
	"fmt"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs3 = Register("FS-3", "", []Tier{TierT2, TierT3}, Twin(Fs3GateClosed, Fs3GateOpen))

// The default world and a reader that leaves the repo.
func fs3WorldSettings() *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{Name: "leaver", Instances: []string{"evsr"}})
	return settings
}

// See the file header.
func Fs3GateClosed(net *Net) *Schedule {
	schedule := fs3Schedule(net, true)
	schedule.Refuses = "writerA's push of x.txt under generation 1, 412 GATE_CLOSED after a reader left and writerB rotated"
	return schedule
}

// See the file header.
func Fs3GateOpen(net *Net) *Schedule {
	return fs3Schedule(net, false)
}

func fs3Schedule(net *Net, drop bool) *Schedule {
	world := NewEvsWorld(net, fs3WorldSettings())
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs3 x 1", 100))},
		{Actor: "writerB", Action: world.Write("writerB", "y.txt", EvsWorldContent("fs3 y 1", 100))},
		{Actor: "writerA", Action: world.WriteAny("writerA", "x.txt", EvsWorldContent("fs3 x 2", 100)), Background: true},
		// x.txt's creation passes
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore, AwaitSkip: 1},
	}
	if drop {
		steps = append(steps, &Step{Actor: "admin", Action: world.DropReader("leaver")})
	}
	steps = append(steps, []*Step{
		{Actor: "writerB", Action: world.Write("writerB", "y.txt", EvsWorldContent("fs3 y 2", 100))},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
		{Release: []string{evsservice.BarrierHeadCasBefore}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectCommitted("writerA", "x.txt")},
		{Actor: "check", Action: world.Expect("A's first push id", func(ctx context.Context) error {
			return fs3FirstPush(world, drop)
		})},
		{Actor: "reader", Action: world.Verify("reader", "x.txt", "y.txt")},
	}...)
	return &Schedule{Id: "FS-3", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// writerA's push of x.txt: with the gate closed its first push id answered 412 GATE_CLOSED, recorded, and a second
// committed; with it open the first committed.
func fs3FirstPush(world *EvsWorld, drop bool) error {
	pushes := world.DevicePushes("writerA")
	if len(pushes) < 2 {
		return fmt.Errorf("writerA posted %d pushes", len(pushes))
	}
	first := pushes[1]
	_, committed := world.committedVersionOf(first.PushId)
	if !drop {
		if !committed || len(pushes) != 2 {
			return fmt.Errorf("with the gate open the push did not commit under its first push id: %v", first.Answers)
		}
		return nil
	}
	if committed {
		return fmt.Errorf("the push under generation 1 committed after the gate closed: %v", first.Answers)
	}
	for _, answer := range first.InstanceAnswers() {
		if answer.Code == protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED {
			return nil
		}
	}
	return fmt.Errorf("its first push id answered %v, not GATE_CLOSED", first.Answers)
}

// See the file header.
func Fs3StepSevenPastFiveSeconds(net *Net) *Schedule {
	schedule := fs3StepSevenSchedule(net, true)
	schedule.Refuses = "writerA's push of x.txt under generation 1, 412 GATE_CLOSED at its rerun past step 7's window after a reader left"
	schedule.Twin = Fs3StepSevenGateOpen
	return schedule
}

// See the file header.
func Fs3StepSevenGateOpen(net *Net) *Schedule {
	return fs3StepSevenSchedule(net, false)
}

func fs3StepSevenSchedule(net *Net, drop bool) *Schedule {
	world := NewEvsWorld(net, fs3WorldSettings())
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "x.txt", EvsWorldContent("fs3 x 1", 100))},
		{Actor: "writerA", Action: world.WriteAny("writerA", "x.txt", EvsWorldContent("fs3 x 2", 100)), Background: true},
		// x.txt's creation passes
		{Actor: "evs1", Await: evsservice.BarrierPushStep6After, AwaitSkip: 1},
	}
	if drop {
		steps = append(steps, &Step{Actor: "admin", Action: world.DropReader("leaver")})
	}
	steps = append(steps, []*Step{
		{Advance: 25 * time.Second},
		{Release: []string{evsservice.BarrierPushStep6After}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectCommitted("writerA", "x.txt")},
		{Actor: "check", Action: world.Expect("A's first push id", func(ctx context.Context) error {
			return fs3FirstPush(world, drop)
		})},
		{Actor: "reader", Action: world.Verify("reader", "x.txt")},
	}...)
	return &Schedule{Id: "FS-3 step 7 past 5 s", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
