// FS-57 (§22.8; §11.8's step 6 and unknown rows, §11.13's resolve row, I-EVS-2; EVS1-M2-40) on the evs world
// (evs_world.go). FS-57 is on §22.8's unknown list, so every write each clause issues also runs with its response lost.
//
// The registered case, Fs57SecondRecordCommits: writerA's push P reaches evs1, whose batch PUT applies and loses its
// answer; evs1's read-back finds its bytes, so it goes on, and it is killed at its head CAS, so the lb sends P on to
// evs2, which writes a second record of P and commits it. evs1 is started again, and writerA's push Q reaches it and
// is held at its head CAS past the lb's 30 s read timeout, so the lb sends Q to evs2, which writes a second record and
// commits; released, evs1's delayed head PUT fails its precondition, its reread finds Q committed and it answers
// that version, which no device hears. 26 h on, evacuation keeps each committed copy and drops the other. The reader
// reads both throughout.
//
// The clause beside it, Fs57StoreUnreachable: every batch PUT fails before the store takes it, on every instance, so
// P answers 503 every attempt and nothing commits. Under the unknown rule a failed PUT runs again as one
// the store applied and whose answer was lost, and then the batch writer's read-back finds its record and P may
// commit, which the clause allows only with that record in the store.
//
// The row's T3 Delay is a barrier here, since a real store parks no request on a schedule's word.

package fault

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs57 = Register("FS-57", "", []Tier{TierT2, TierT3}, Fs57SecondRecordCommits)

// The batch minute directory every batch is under: pb/.
const fs57BatchPrefix = "pb/"

// See the file header.
func Fs57SecondRecordCommits(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerB", Action: world.Write("writerB", "base.txt", EvsWorldContent("fs57 base", 100))},
		{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: fs57BatchPrefix, Result: ApplyThenDrop, Actor: "evs1", WritesOnly: true}},
		{Actor: "writerA", Action: world.WriteAny("writerA", "p.txt", EvsWorldContent("fs57 p", 300)), Background: true},
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore},
		{Actor: "evs1", Kill: true},
		{Actor: "writerA", Join: true},
		{Actor: "check", Action: world.Expect("evs2 committed a second record of P", func(ctx context.Context) error {
			return fs57TwoRecords(ctx, world, "p.txt", 0)
		})},
		{Actor: "reader", Action: world.Verify("reader", "base.txt", "p.txt")},
		{Actor: "evs1", Restart: "evs1"},
		{Actor: "writerA", Action: world.WriteAny("writerA", "q.txt", EvsWorldContent("fs57 q", 300)), Background: true},
		// the second arm on evs1's CAS: Q's
		{Actor: "evs1", Await: evsservice.BarrierHeadCasBefore},
		{Advance: 30 * time.Second},
		{Actor: "writerA", Join: true},
		{Actor: "reader", Action: world.Verify("reader", "p.txt", "q.txt")},
		{Release: []string{evsservice.BarrierHeadCasBefore}},
		{Actor: "check", Action: world.Expect("evs1's delayed head PUT failed and it answered Q's version", func(ctx context.Context) error {
			return fs57TwoRecords(ctx, world, "q.txt", http.StatusOK)
		})},
		{Actor: "reader", Action: world.Verify("reader", "p.txt", "q.txt")},
		{Advance: 26 * time.Hour},
		{Actor: "evacuator", Action: world.Evacuate()},
		{Actor: "check", Action: world.Expect("evacuation took every record of P and Q out of the batches", func(ctx context.Context) error {
			for _, pushId := range world.DevicePushIds("writerA") {
				count, err := world.BatchRecordCount(ctx, pushId)
				if err != nil {
					return err
				}
				if count != 0 {
					return fmt.Errorf("push %s keeps %d records in batches", pushId, count)
				}
			}
			return nil
		})},
		{Actor: "reader", Action: world.Verify("reader", "base.txt", "p.txt", "q.txt")},
	}
	return &Schedule{Id: "FS-57", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// path's write committed under one push id, at evs2, with two of its records in batches, and evs1 answered it
// evs1Status, or nothing when that is 0.
func fs57TwoRecords(ctx context.Context, world *EvsWorld, path string, evs1Status int) error {
	version, pushId, err := world.CommittedVersion("writerA", path)
	if err != nil {
		return err
	}
	for _, push := range world.DevicePushes("writerA") {
		if push.PushId != pushId {
			continue
		}
		evs1Answered, evs2Committed := false, false
		for _, answer := range push.InstanceAnswers() {
			switch answer.Instance {
			case "evs1":
				evs1Answered = answer.Status == evs1Status && (evs1Status != http.StatusOK || answer.Version == version)
				if evs1Status == 0 {
					return fmt.Errorf("evs1, killed at its CAS, answered %s", answer)
				}
			case "evs2":
				evs2Committed = answer.Committed(version)
			}
		}
		if (!evs1Answered && evs1Status != 0) || !evs2Committed {
			return fmt.Errorf("answers %v for a commit at %d", push.InstanceAnswers(), version)
		}
	}
	count, err := world.BatchRecordCount(ctx, pushId)
	if err != nil {
		return err
	}
	if count != 2 {
		return fmt.Errorf("%d records of the push in batches, not 2", count)
	}
	return nil
}

// See the file header.
func Fs57StoreUnreachable(net *Net) *Schedule {
	world := NewEvsWorld(net, nil)
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerB", Action: world.Write("writerB", "base.txt", EvsWorldContent("fs57 base", 100))},
		// every instance's batch PUT from here on: one plan, so a run in which an applied PUT lets evs1 commit leaves
		// no plan unfired
		{Fault: &FaultPlan{Op: sidecartest.FaultOpPut, KeyPrefix: fs57BatchPrefix, Result: FailBeforeApply, Repeat: -1}},
		{Actor: "writerA", Action: world.WriteAny("writerA", "p.txt", EvsWorldContent("fs57 p", 300))},
		{Actor: "check", Action: world.Expect("P answered 503 and committed only from a record the store holds", func(ctx context.Context) error {
			answers, pushId, err := world.NewestAnswers("writerA")
			if err != nil {
				return err
			}
			records, err := world.BatchRecordCount(ctx, pushId)
			if err != nil {
				return err
			}
			_, committed := world.committedVersionOf(pushId)
			if records == 0 {
				// every batch PUT failed before the store took it
				for _, answer := range answers {
					if answer.Status != http.StatusServiceUnavailable {
						return fmt.Errorf("an attempt answered %s with no record written", answer)
					}
				}
				if committed {
					return fmt.Errorf("P committed with no record written")
				}
			}
			return nil
		})},
		{Actor: "reader", Action: world.Verify("reader", "base.txt", "p.txt")},
	}
	return &Schedule{Id: "FS-57 store unreachable", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
