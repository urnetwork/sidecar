// FS-113 (§22.8; D-EVS-23's stable refusals, §11.8's refuse row, I-EVS-3; EVS1-M2-40) on the evs world (evs_world.go),
// every instance on one clock.
//
// The registered case, Fs113RecordedRefusal, beside its twin: attempt A of writerA's push P, a change sealed under
// generation 1, reaches evs1 and is held at arrival, before its handler does anything; evs1 holds its projection where
// it is while a reader leaves the repo, so evs2's fresh projection closes the gate on P's generation (5d's predicate,
// a recorded refusal) and evs1's stale one does not; the lb's read timeout passes, so its re-send B reaches evs2,
// which refuses P 412 GATE_CLOSED, records it in the head and is held with its answer unsent until A starts. A is released 150 ms after the record:
// its step 4 reads the head with the record, and it answers B's refusal with recorded: true, though its own gate
// passes P; then B's answer reaches writerA, which builds the write again under a new push id and the next
// generation. P never commits. The twin, Fs113CommitFirst: B is held before its recording CAS instead, A is released
// and commits P, and B's CAS then fails, its reread finds P committed and it answers 200 with P's version, which is
// what writerA hears.
//
// FS-113 also names the cached-head form of A, a multipart seal, each other recorded refusal, the lb's own re-send
// on T3 (warp's nginx, not this world's model of it), a record lapsing past P's until, 8 live records and one under
// 1 s answering 429, TIME_AHEAD, and a push creating its ref: EVS1-M2-40's report keeps them. FI-2 holds through
// the world's checks (TEST-M2-04), and so does FI-3 (TEST-M2-05).

package fault

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
)

var Fs113 = Register("FS-113", "", []Tier{TierT2, TierT3}, Twin(Fs113RecordedRefusal, Fs113CommitFirst))

// See the file header.
func Fs113RecordedRefusal(net *Net) *Schedule {
	world := NewEvsWorld(net, fs113WorldSettings())
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "p.txt", EvsWorldContent("fs113 p 1", 100))},
		{Actor: "writerA", Action: world.WriteAny("writerA", "p.txt", EvsWorldContent("fs113 p 2", 100)), Background: true},
		// p.txt's creation arrived first
		{Actor: "evs1", Await: evsservice.BarrierPushArrive, AwaitSkip: 1},
		{Actor: "evs1", Action: world.HoldView("evs1")},
		{Actor: "admin", Action: world.DropReader("leaver")},
		{Advance: 30 * time.Second},
		{Actor: "evs2", Await: evsservice.BarrierPushRefuseAfter},
		{Advance: 150 * time.Millisecond},
		{Release: []string{evsservice.BarrierPushArrive}},
		{Actor: "check", Action: world.Expect("A answered B's recorded refusal", func(ctx context.Context) error {
			return fs113Answers(world, protocol.EvsRefusalCode_EVS_REFUSAL_GATE_CLOSED)
		})},
		{Release: []string{evsservice.BarrierPushRefuseAfter}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.Expect("P never committed", func(ctx context.Context) error {
			pushIds := world.DevicePushIds("writerA")
			for _, pushId := range pushIds[1:2] {
				if _, committed := world.committedVersionOf(pushId); committed {
					return fmt.Errorf("P committed after its recorded refusal")
				}
			}
			return nil
		})},
		{Actor: "reader", Action: world.Verify("reader", "p.txt")},
	}
	return &Schedule{
		Id: "FS-113", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3},
		Refuses: "push P, recorded refused 412 GATE_CLOSED by the lb's re-send on evs2, its held first attempt answering the record",
	}
}

// The default world and a reader that leaves the repo.
func fs113WorldSettings() *EvsWorldSettings {
	settings := DefaultEvsWorldSettings()
	settings.Devices = append(settings.Devices, &EvsWorldDeviceSettings{Name: "leaver", Instances: []string{"evsr"}})
	return settings
}

// A's answer on evs1 is a refusal with code and recorded: true, and P, writerA's second push, is not committed.
func fs113Answers(world *EvsWorld, code protocol.EvsRefusalCode) error {
	pushes := world.DevicePushes("writerA")
	if len(pushes) < 2 {
		return fmt.Errorf("writerA posted %d pushes", len(pushes))
	}
	answers, pushId := pushes[1].InstanceAnswers(), pushes[1].PushId
	evs1Recorded := false
	for _, answer := range answers {
		if answer.Instance == "evs1" && answer.Code == code && answer.Recorded {
			evs1Recorded = true
		}
		if answer.Status == http.StatusOK {
			return fmt.Errorf("an attempt of P answered %s", answer)
		}
	}
	if !evs1Recorded {
		return fmt.Errorf("evs1 answered %v, not the recorded refusal", answers)
	}
	if _, committed := world.committedVersionOf(pushId); committed {
		return fmt.Errorf("P committed after its recorded refusal")
	}
	return nil
}

// See the file header.
func Fs113CommitFirst(net *Net) *Schedule {
	world := NewEvsWorld(net, fs113WorldSettings())
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "p.txt", EvsWorldContent("fs113 p 1", 100))},
		{Actor: "writerA", Action: world.WriteAny("writerA", "p.txt", EvsWorldContent("fs113 p 2", 100)), Background: true},
		{Actor: "evs1", Await: evsservice.BarrierPushArrive, AwaitSkip: 1},
		{Actor: "evs1", Action: world.HoldView("evs1")},
		{Actor: "admin", Action: world.DropReader("leaver")},
		{Advance: 30 * time.Second},
		{Actor: "evs2", Await: evsservice.BarrierPushRefuseBefore},
		{Release: []string{evsservice.BarrierPushArrive}},
		{Actor: "check", Action: world.Expect("A committed P", func(ctx context.Context) error {
			answers, pushId, err := world.NewestAnswers("writerA")
			if err != nil {
				return err
			}
			version, committed := world.committedVersionOf(pushId)
			if !committed {
				return fmt.Errorf("P is not committed: %v", answers)
			}
			for _, answer := range answers {
				if answer.Instance == "evs1" && answer.Committed(version) {
					return nil
				}
			}
			return fmt.Errorf("evs1 answered %v, not 200 at %d", answers, version)
		})},
		{Release: []string{evsservice.BarrierPushRefuseBefore}},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.ExpectCommitted("writerA", "p.txt")},
		{Actor: "check", Action: world.Expect("B found P committed and answered its version", func(ctx context.Context) error {
			version, pushId, err := world.CommittedVersion("writerA", "p.txt")
			if err != nil {
				return err
			}
			answers, newest, err := world.NewestAnswers("writerA")
			if err != nil || newest != pushId {
				return fmt.Errorf("writerA's newest push is not the committed one: %v", err)
			}
			for _, answer := range answers {
				if answer.Instance == "evs2" && answer.Committed(version) {
					return nil
				}
			}
			return fmt.Errorf("evs2 answered %v, not 200 at %d", answers, version)
		})},
		{Actor: "reader", Action: world.Verify("reader", "p.txt")},
	}
	return &Schedule{Id: "FS-113", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
