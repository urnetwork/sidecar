// FS-60 (§22.8, FI-1, FI-13 (c); EVSB-M2-11) on the evs world (evs_world.go): the hourly evacuation over one repo's
// history as the real client and engine write it, a run killed at a request a schedule names by a plan on the
// evacuator's actor: the request never applies and the run ends there, and the next run resumes from the store.
// FI-1's closure, which finds each committed record in its batch, its parcel or its pack as a reader would, runs after
// every step with every check the world names, so a reader at each step finds every record; the reader reads every
// path at each stage too.
//
// The registered case, Fs60KilledAfterThePackAndBeforeTheBatchDelete: three pushes' records, 25 h old, packed by a run
// that dies after its pack and before its pidx/ entry, then by one that dies after the entry and before its first
// batch delete; the run after them packs nothing again and deletes the three batches, leaving one pack and one entry.
//
// The clauses beside it (clauses.go): a pending record on an idle ref, a push whose only instance was killed at its
// head CAS, fenced and then dropped, the head's fence raised at the run's time with no version changed; and a small
// repo's parcels packed at 7 d, the replacement killed between the pack's entries and the parcel's delete, both
// standing and readers taking the pack's entry, the next run deleting the parcel and its entry without packing again.
//
// FI-13 (c), the store's count against LIST sizes, is QUOTA-M2-13's oracle and unbound (fault.FI(13) fails closed),
// and the nightly count it reads is EVSB-M2-12's, which fs60_nightly_test.go runs on its own world; so these schedules
// name FI-1 and the world's checks, not FI-13. The row's other clauses (a shredded repo's records dropped and a deleted
// repo's kept, a held network's packed and not deleted, a seal evacuated a run after its parts, a run restarted once a
// log page has turned 24 h old) still run in fs60_test.go on its hand-written world, outside the registry. On T3
// server's evshost runs these builders on the local stack's MinIO, ages read through T3's store clock.

package fault

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/urnetwork/sidecar/evsservice"
	"github.com/urnetwork/sidecar/protocol"
	"github.com/urnetwork/sidecar/sidecartest"
)

var Fs60 = Register("FS-60", "", []Tier{TierT2, TierT3}, Fs60KilledAfterThePackAndBeforeTheBatchDelete)

// Every repo's aged material packs, however small: the evacuator's pack threshold at a byte.
func fs60PackAll(settings *evsservice.EvacuatorSettings) {
	settings.PackByteCount = 1
}

// A plan that kills the evacuator at its nth request of op under keyPrefix: the request never applies and the run
// ends there. A create is sent once more after a read shows it never landed (sidecar.PutImmutable), so a kill at a PUT
// fails that one too.
func fs60Kill(op string, keyPrefix string, nth int) *FaultPlan {
	plan := &FaultPlan{Op: op, KeyPrefix: keyPrefix, Nth: nth, Result: FailBeforeApply, Actor: "evacuator"}
	if op == sidecartest.FaultOpPut {
		plan.Repeat = 1
	}
	return plan
}

// See the file header.
func Fs60KilledAfterThePackAndBeforeTheBatchDelete(net *Net) *Schedule {
	// past the 25 h mark of a minute just written, and a minute more: the run then takes it
	aged := 25*time.Hour + 2*time.Minute
	world := NewEvsWorld(net, nil)
	paths := []string{"a.txt", "b.txt", "c.txt"}
	// the batches the three pushes left, which the kills must not delete
	batchKeys := []string{}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs60 a", 300))},
		{Actor: "writerB", Action: world.Write("writerB", "b.txt", EvsWorldContent("fs60 b", 300))},
		{Actor: "writerA", Action: world.Write("writerA", "c.txt", EvsWorldContent("fs60 c", 300))},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			keys, err := world.StoredKeys(ctx, net, false, evsWorldBatchPrefix)
			if err != nil {
				return err
			}
			if len(keys) == 0 {
				return fmt.Errorf("the pushes left no batch")
			}
			batchKeys = keys
			return nil
		}},
		{Advance: aged},
		{Actor: "reader", Action: world.Verify("reader", paths...)},
		// the pack lands and the run dies before its pidx/ entry
		{Fault: fs60Kill(sidecartest.FaultOpPut, evsWorldEntryPrefix, 1)},
		{Actor: "evacuator", Action: world.EvacuateKilled(fs60PackAll)},
		{Actor: "check", Action: world.ExpectStoredKeyCount("packs after the first kill", true, evsWorldPackPrefix, 1)},
		{Actor: "check", Action: world.ExpectStoredKeyCount("entries past the first kill", false, evsWorldEntryPrefix, 0)},
		{Actor: "reader", Action: world.Verify("reader", paths...)},
		// the entry lands and the run dies before its first batch delete
		{Fault: fs60Kill(sidecartest.FaultOpDelete, evsWorldBatchPrefix, 1)},
		{Actor: "evacuator", Action: world.EvacuateKilled(fs60PackAll)},
		{Actor: "check", Action: world.ExpectStoredKeyCount("entries after the second kill", false, evsWorldEntryPrefix, 1)},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			keys, err := world.StoredKeys(ctx, net, false, evsWorldBatchPrefix)
			if err != nil {
				return err
			}
			if !slices.Equal(keys, batchKeys) {
				return fmt.Errorf("a batch went past the second kill: %v, were %v", keys, batchKeys)
			}
			return nil
		}},
		{Actor: "reader", Action: world.Verify("reader", paths...)},
		{Actor: "evacuator", Action: world.EvacuateWith(fs60PackAll, func(result *evsservice.EvacuationResult) error {
			if result.PackCount != 0 || result.BatchDeletedCount != len(batchKeys) || result.HasBatches {
				return fmt.Errorf("the run after the kills packed again or left a batch, %d batches stood", len(batchKeys))
			}
			return nil
		})},
		{Actor: "check", Action: world.ExpectStoredKeyCount("packs after the batches went", true, evsWorldPackPrefix, 1)},
		{Actor: "check", Action: world.ExpectStoredKeyCount("entries after the batches went", false, evsWorldEntryPrefix, 1)},
		{Actor: "reader", Action: world.Verify("reader", paths...)},
	}
	return &Schedule{Id: "FS-60", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header. writerB's only instance is evs3, so the lb has no instance to send its push on to once evs3 is
// killed at the push's head CAS: its record stays in its batch, committed by no head, and the ref stays idle.
func Fs60PendingRecordFencedThenDropped(net *Net) *Schedule {
	settings := DefaultEvsWorldSettings()
	settings.Devices = []*EvsWorldDeviceSettings{
		{Name: "writerA", Instances: []string{"evs1", "evs2"}, Writer: true},
		{Name: "writerB", Instances: []string{"evs3"}, Writer: true},
		{Name: "reader", Instances: []string{"evsr"}},
	}
	aged := 25*time.Hour + 2*time.Minute
	world := NewEvsWorld(net, settings)
	// the head before the run that fences it
	var before *protocol.EvsHead
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs60 pending a", 300))},
		{Actor: "writerB", Action: world.WriteAny("writerB", "p.txt", EvsWorldContent("fs60 pending p", 300)), Background: true},
		{Actor: "evs3", Await: evsservice.BarrierHeadCasBefore},
		{Actor: "evs3", Kill: true},
		{Actor: "writerB", Join: true},
		{Actor: "check", Action: world.Expect("the pending push's record stands in its batch, committed by no head", func(ctx context.Context) error {
			if _, _, err := world.CommittedVersion("writerB", "p.txt"); err == nil {
				return fmt.Errorf("writerB's push committed with its only instance killed")
			}
			pushIds := world.DevicePushIds("writerB")
			if len(pushIds) != 1 {
				return fmt.Errorf("writerB posted %d pushes", len(pushIds))
			}
			count, err := world.BatchRecordCount(ctx, pushIds[0])
			if err != nil {
				return err
			}
			if count != 1 {
				return fmt.Errorf("the pending push has %d records in batches", count)
			}
			before, err = world.Head(ctx)
			return err
		})},
		{Actor: "reader", Action: world.Verify("reader", "a.txt")},
		{Advance: aged},
		{Actor: "evacuator", Action: world.EvacuateWith(nil, func(result *evsservice.EvacuationResult) error {
			if result.FenceCount != 1 || result.DeadCount != 1 || result.KeptCount != 1 || result.HasBatches {
				return fmt.Errorf("the pending record was not fenced and dropped beside the committed one")
			}
			return nil
		})},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			after, err := world.Head(ctx)
			if err != nil {
				return err
			}
			if after.GetVersion() != before.GetVersion() || after.GetFence() != before.GetFence()+1 || after.GetFenceMs() != net.Clock().Now().UnixMilli() {
				return fmt.Errorf("the fence wrote version %d (was %d), fence %d (was %d), fence_ms %d", after.GetVersion(), before.GetVersion(), after.GetFence(), before.GetFence(), after.GetFenceMs())
			}
			count, err := world.BatchRecordCount(ctx, world.DevicePushIds("writerB")[0])
			if err != nil {
				return err
			}
			if count != 0 {
				return fmt.Errorf("the dead record still stands in %d batches", count)
			}
			return nil
		}},
		{Actor: "reader", Action: world.Verify("reader", "a.txt")},
	}
	return &Schedule{Id: "FS-60 pending record fenced then dropped", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}

// See the file header. The second push is late enough that its evacuation comes as the first record nears 7 d, and
// the replacement's first DELETE is the parcel's entry.
func Fs60ParcelsPackAtSevenDays(net *Net) *Schedule {
	aged := 25*time.Hour + 2*time.Minute
	world := NewEvsWorld(net, nil)
	// the first record's parcel, which stands until the run after the kill
	parcelKeys := []string{}
	steps := []*Step{
		{Actor: "writerA", Action: world.Setup},
		{Actor: "writerA", Action: world.Write("writerA", "a.txt", EvsWorldContent("fs60 seven a", 300))},
		{Advance: aged},
		{Actor: "evacuator", Action: world.EvacuateWith(nil, func(result *evsservice.EvacuationResult) error {
			if result.ParcelCount != 1 || result.PackCount != 0 {
				return fmt.Errorf("the first record did not go to a parcel")
			}
			return nil
		})},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			keys, err := world.StoredKeys(ctx, net, false, evsWorldParcelPrefix)
			if err != nil {
				return err
			}
			if len(keys) != 1 {
				return fmt.Errorf("parcels after the first run: %v", keys)
			}
			parcelKeys = keys
			return nil
		}},
		// the clock at 7 d less 26 h from the first record
		{Advance: 7*24*time.Hour - 26*time.Hour - aged},
		{Actor: "writerB", Action: world.Write("writerB", "b.txt", EvsWorldContent("fs60 seven b", 300))},
		{Advance: aged},
		// the pack and its entry land, and the run dies at the parcel's delete: its entry's DELETE is the first
		{Fault: fs60Kill(sidecartest.FaultOpDelete, evsWorldEntryPrefix, 1)},
		{Actor: "evacuator", Action: world.EvacuateKilled(nil)},
		{Actor: "check", Action: world.ExpectStoredKeyCount("packs after the kill", true, evsWorldPackPrefix, 1)},
		{Actor: "check", Action: func(ctx context.Context, net *Net) error {
			keys, err := world.StoredKeys(ctx, net, false, evsWorldParcelPrefix)
			if err != nil {
				return err
			}
			if !slices.Equal(keys, parcelKeys) {
				return fmt.Errorf("the parcel went past the kill: %v, was %v", keys, parcelKeys)
			}
			return nil
		}},
		{Actor: "check", Action: world.ExpectStoredKeyCount("the pack's and the parcel's entries", false, evsWorldEntryPrefix, 2)},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "b.txt")},
		{Actor: "evacuator", Action: world.EvacuateWith(nil, func(result *evsservice.EvacuationResult) error {
			if result.PackCount != 0 || result.ReplacedParcelCount != 1 || result.HasBatches {
				return fmt.Errorf("the run after the kill packed again or kept the parcel")
			}
			return nil
		})},
		{Actor: "check", Action: world.ExpectStoredKeyCount("parcels after the replacement", false, evsWorldParcelPrefix, 0)},
		{Actor: "check", Action: world.ExpectStoredKeyCount("entries after the replacement", false, evsWorldEntryPrefix, 1)},
		{Actor: "reader", Action: world.Verify("reader", "a.txt", "b.txt")},
	}
	return &Schedule{Id: "FS-60 parcels pack at seven days", Steps: steps, Check: world.Checks(), Tiers: []Tier{TierT2, TierT3}}
}
